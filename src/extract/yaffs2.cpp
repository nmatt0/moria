// yaffs2.cpp — YAFFS2 read-only extraction. See yaffs2.hpp.
//
// Layout (little-endian, standard MTD OOB scheme): the image is chunks of
// (pagesize data + sparesize OOB). Packed tags sit at OOB offset 2:
//   u32 sequenceNumber @2, u32 objectId @6, u32 chunkId @10, u32 byteCount @14.
// chunkId 0 = object header; its data area is a yaffs_ObjectHeader:
//   u32 type @0 (1 file, 2 symlink, 3 dir, 4 hardlink, 5 special),
//   u32 parentObjectId @4, u16 nameSum @8, char name[256] @10,
//   u32 mode @266, ... u32 fileSizeLow @290, u32 equivObjectId @294,
//   char alias[160] @298 (symlink target).
// chunkId >= 1 = file data at (chunkId-1)*pagesize, byteCount bytes. Objects are
// reassembled newest-wins (later image position = newer); the tree is walked
// from the root object id 1. All disk access is range-checked through Reader.
#include "extract/yaffs2.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint32_t YAFFS_ROOT = 1;
constexpr uint32_t TYPE_FILE = 1;
constexpr uint32_t TYPE_SYMLINK = 2;
constexpr uint32_t TYPE_DIR = 3;
constexpr uint32_t TYPE_HARDLINK = 4;

// Object-header field offsets within the chunk data area.
constexpr size_t OH_TYPE = 0;
constexpr size_t OH_PARENT = 4;
constexpr size_t OH_NAME = 10;
constexpr size_t OH_NAME_MAX = 255;
// name[256] ends at 266; the struct pads 2 bytes to 4-align the u32 fields, so
// mode is at 268 (not 266). Verified empirically against mkyaffs2 output.
constexpr size_t OH_MODE = 268;
constexpr size_t OH_FILESIZE = 292;
constexpr size_t OH_ALIAS = 300;
constexpr size_t OH_ALIAS_MAX = 159;

// Packed-tags offset within the OOB. The MTD ecclayout reserves 2 bytes before
// the tags on larger OOBs (>=32B); a tight 16-byte OOB holds the 16-byte tags at
// offset 0. Detection tries both.

constexpr size_t MAX_CHUNKS = 20000000;
constexpr size_t MAX_DEPTH = 128;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(4) << 30;

struct Object {
    uint32_t type = 0;
    uint32_t parent = 0;
    uint32_t mode = 0;
    uint64_t size = 0;
    std::string name;
    std::string alias;  // symlink target
    bool seen = false;
    std::map<uint32_t, size_t> data;  // chunkId(>=1) -> absolute data offset (newest wins)
    uint32_t data_bytes_last = 0;     // byteCount of the highest chunkId
    uint32_t last_chunk = 0;
};

struct Geometry {
    size_t page = 0;
    size_t spare = 0;
    size_t stride = 0;
    size_t tag_off = 2;  // packed-tags offset within the OOB
};

struct Ctx {
    const Reader& r;
    uint64_t base;
    uint64_t end;
    Geometry g;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    std::map<uint32_t, Object> objs{};
    std::map<uint32_t, std::vector<uint32_t>> children{};  // parent -> child ids
    std::set<uint32_t> stack{};
};

// Read a NUL-terminated string of at most `max` bytes from chunk data at abs `off`.
std::string read_str(const Reader& r, uint64_t off, size_t max) {
    auto b = r.bytes(off, max);
    if (!b) return {};
    std::string s(reinterpret_cast<const char*>(b->data()), max);
    if (auto z = s.find('\0'); z != std::string::npos) s.resize(z);
    return s;
}

std::optional<uint32_t> u32(const Reader& r, uint64_t off) {
    return r.at<uint32_t>(off, Endian::Little);
}

// yaffs2 packs "extra header info" into an object-header chunk's tag: chunkId
// carries EXTRA_HEADER_INFO_FLAG (bit 31) with the parent id in the low bits,
// and objectId's top nibble holds the object type. So a header chunk's stored
// chunkId is not literally 0, and its objectId must be masked to the real id.
constexpr uint32_t YAFFS_EXTRA_HEADER_FLAG = 0x8000'0000u;
constexpr uint32_t YAFFS_OBJECTID_MASK = 0x0fff'ffffu;
bool is_header_chunkid(uint32_t c) { return c == 0 || (c & YAFFS_EXTRA_HEADER_FLAG); }

// Detect (page, spare). Standard NAND geometries; pick the first where the whole
// image divides evenly and chunk 0 parses as an object header (type 1..5) with a
// sane tag (objectId >= 1, header chunkId) at the MTD tag offset.
bool detect_geometry(Ctx& c) {
    static const std::pair<size_t, size_t> GEOS[] = {
        {2048, 64}, {2048, 128}, {4096, 128}, {4096, 224}, {512, 16}, {2048, 32}, {8192, 256},
    };
    const uint64_t avail = c.end - c.base;
    for (auto [page, spare] : GEOS) {
        const size_t stride = page + spare;
        if (avail < stride || avail % stride != 0) continue;
        auto type = u32(c.r, c.base + OH_TYPE);
        if (!type || *type < 1 || *type > 5) continue;
        for (size_t tag_off : {size_t(2), size_t(0)}) {
            if (tag_off + 16 > spare) continue;
            auto objid = u32(c.r, c.base + page + tag_off + 4);
            auto chunkid = u32(c.r, c.base + page + tag_off + 8);
            if (!objid || !chunkid) continue;
            if (*objid == 0xffffffff || (*objid & YAFFS_OBJECTID_MASK) < 1 ||
                !is_header_chunkid(*chunkid))
                continue;
            c.g = {page, spare, stride, tag_off};
            return true;
        }
    }
    return false;
}

void scan_chunks(Ctx& c) {
    const size_t page = c.g.page, stride = c.g.stride;
    const uint64_t nchunks = (c.end - c.base) / stride;
    for (uint64_t i = 0; i < nchunks; ++i) {
        if (i > MAX_CHUNKS) { c.truncated = true; break; }
        const uint64_t chunk = c.base + i * stride;
        const uint64_t tag = chunk + page + c.g.tag_off;
        auto objid = u32(c.r, tag + 4);
        auto chunkid = u32(c.r, tag + 8);
        auto bytecount = u32(c.r, tag + 12);
        if (!objid || !chunkid || !bytecount) continue;
        if (*objid == 0 || *objid == 0xffffffff) continue;  // unused/erased
        const uint32_t oid = *objid & YAFFS_OBJECTID_MASK;  // strip packed type bits

        if (is_header_chunkid(*chunkid)) {  // object header (chunkId 0, maybe extra-encoded)
            auto type = u32(c.r, chunk + OH_TYPE);
            auto parent = u32(c.r, chunk + OH_PARENT);
            auto mode = u32(c.r, chunk + OH_MODE);
            if (!type || !parent || *type < 1 || *type > 5) continue;
            Object& o = c.objs[oid];
            o.seen = true;  // later header wins (newest)
            o.type = *type;
            o.parent = *parent;
            o.mode = mode.value_or(0);
            o.name = read_str(c.r, chunk + OH_NAME, OH_NAME_MAX);
            if (*type == TYPE_FILE) {
                auto sz = u32(c.r, chunk + OH_FILESIZE);
                o.size = sz.value_or(0);
            } else if (*type == TYPE_SYMLINK) {
                o.alias = read_str(c.r, chunk + OH_ALIAS, OH_ALIAS_MAX);
            }
        } else {  // data chunk
            const uint32_t cid = *chunkid;
            Object& o = c.objs[oid];
            o.data[cid] = static_cast<size_t>(chunk);  // newest position wins
            if (cid >= o.last_chunk) {
                o.last_chunk = cid;
                o.data_bytes_last = *bytecount;
            }
        }
    }
    // Build the parent -> children index over objects that have a header.
    for (auto& [id, o] : c.objs)
        if (o.seen) c.children[o.parent].push_back(id);
}

void build_file(Ctx& c, const Object& o, std::vector<uint8_t>& out) {
    uint64_t size = o.size;
    if (size > MAX_FILE_BYTES) { size = MAX_FILE_BYTES; c.truncated = true; }
    out.assign(size, 0);
    const size_t page = c.g.page;
    for (auto& [cid, off] : o.data) {
        if (cid == 0) continue;
        uint64_t pos = uint64_t(cid - 1) * page;
        if (pos >= size) continue;
        uint64_t want = std::min<uint64_t>(page, size - pos);
        auto d = c.r.bytes(off, static_cast<size_t>(want));
        if (!d) { c.truncated = true; continue; }
        std::memcpy(out.data() + pos, d->data(), static_cast<size_t>(want));
    }
}

void walk(Ctx& c, uint32_t parent, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (!c.stack.insert(parent).second) return;  // cycle guard
    auto it = c.children.find(parent);
    if (it != c.children.end()) {
        for (uint32_t id : it->second) {
            auto oi = c.objs.find(id);
            if (oi == c.objs.end() || !oi->second.seen) continue;
            const Object& o = oi->second;
            if (o.name.empty() || o.name == "." || o.name == ".." ||
                o.name.find('/') != std::string::npos)
                continue;
            const std::string child_rel = rel.empty() ? o.name : rel + "/" + o.name;
            const std::string full = c.subdir + "/" + child_rel;
            if (o.type == TYPE_DIR) {
                if (c.root.make_dir(full)) c.out.dirs++;
                walk(c, id, child_rel, depth + 1);
            } else if (o.type == TYPE_SYMLINK) {
                if (!o.alias.empty() && c.root.make_symlink(full, o.alias)) c.out.symlinks++;
            } else if (o.type == TYPE_FILE) {
                std::vector<uint8_t> data;
                build_file(c, o, data);
                if (c.root.write_file(full, data, o.mode & 0777)) {
                    c.out.files++;
                    c.out.bytes += data.size();
                } else {
                    c.out.warnings.push_back("write failed: " + child_rel);
                }
            }
            // hardlink / special: skipped.
        }
    }
    c.stack.erase(parent);
}

}  // namespace

bool extract_yaffs2(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out) {
    out.offset = f.offset;
    out.type = "yaffs2";
    out.root = subdir;

    // Bound the walk to the region identify sized (image_size returns a whole
    // number of chunks), not the whole file. Otherwise a truncated/carved image
    // or a mid-stream region makes (end - base) not a chunk multiple — failing
    // the geometry's even-division check — and, worse, the scan bleeds into the
    // next partition. A yaffs2 finding without a size (data-only) falls back to
    // EOF, where detect_geometry will decline anyway.
    uint64_t end = r.size();
    if (f.size > 0 && f.offset + f.size <= r.size()) end = f.offset + f.size;
    Ctx c{r, f.offset, end, {}, root, subdir, out};
    if (!detect_geometry(c)) {
        // No usable page+OOB geometry: almost certainly a data-only dump whose
        // spare/tags were stripped. Nothing can reconstruct that.
        out.status = "error:no-oob-geometry";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    scan_chunks(c);
    walk(c, YAFFS_ROOT, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

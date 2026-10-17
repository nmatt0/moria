// reiserfs.cpp — ReiserFS (3.5 / 3.6) read-only extraction. See reiserfs.hpp.
//
// Format reference: the kernel on-disk headers (fs/reiserfs/reiserfs.h) and the
// reiserfsprogs layout. Everything on disk is little-endian and packed.
//
// Layout recap:
//   - Superblock at base+64 KiB (3.6, magic "ReIsEr2Fs"/"ReIsEr3Fs") or base+8
//     KiB (3.5, magic "ReIsErFs"). It records block size, block count, the tree
//     height, and the root block number. Block N is at base + N*block_size.
//   - The S+ tree: internal nodes (level > 1) hold nr_item keys followed by
//     nr_item+1 disk_child pointers; leaves (level 1) hold nr_item 24-byte item
//     headers at the front and item bodies packed at the back (located by
//     ih_item_location). We traverse the tree by child pointer only and never
//     interpret an internal key, so the v1/v2 key ambiguity never arises there.
//   - A leaf item's key is (dir_id, objectid, offset, type). ih_version selects
//     the key encoding: v1 (offset u32 + uniqueness u32) or v2 (u64: 60-bit
//     offset + 4-bit type). Objects are the pair (dir_id, objectid); an object's
//     items are its stat-data (type SD, offset 0), its directory entries (type
//     DIRENTRY), and its file bodies (type DIRECT tail + INDIRECT block lists).
//   - Reconstruction: collect all leaf items, index by (dir_id, objectid), then
//     recurse from the root directory key (1, 2), reading each child's stat-data
//     for its mode and rebuilding files from their DIRECT/INDIRECT items.
#include "extract/reiserfs.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

// Superblock location within the partition.
constexpr uint64_t DISK_OFFSET_36 = 64 * 1024;
constexpr uint64_t DISK_OFFSET_35 = 8 * 1024;

// Node levels.
constexpr uint16_t LEAF_LEVEL = 1;
constexpr uint16_t MAX_LEVEL = 16;  // real trees are <= ~5 deep

// Header sizes.
constexpr uint64_t BLKH_SIZE = 24;
constexpr uint64_t KEY_SIZE = 16;
constexpr uint64_t IH_SIZE = 24;
constexpr uint64_t DC_SIZE = 8;
constexpr uint64_t DEH_SIZE = 16;

// stat_data sizes.
constexpr uint64_t SD_V1_SIZE = 32;
constexpr uint64_t SD_V2_SIZE = 44;

// i_mode file-type bits (same encoding as POSIX / ext).
constexpr uint16_t S_IFMT = 0xF000;
constexpr uint16_t S_IFREG = 0x8000;
constexpr uint16_t S_IFDIR = 0x4000;
constexpr uint16_t S_IFLNK = 0xA000;

// Root directory object: (dir_id, objectid) = (ROOT_PARENT, ROOT).
constexpr uint32_t ROOT_PARENT_OBJECTID = 1;
constexpr uint32_t ROOT_OBJECTID = 2;

// v1 key uniqueness values.
constexpr uint32_t V1_SD = 0;
constexpr uint32_t V1_DIRENTRY = 500;
constexpr uint32_t V1_INDIRECT = 0xfffffffe;
constexpr uint32_t V1_DIRECT = 0xffffffff;

// Normalized item type.
enum class IType { SD, Direct, Indirect, DirEntry, Other };

// Guardrails against hostile / corrupt images.
constexpr size_t MAX_NODES = 4000000;
constexpr size_t MAX_ITEMS = 8000000;
constexpr size_t MAX_FILES = 2000000;
constexpr size_t MAX_DEPTH = 128;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;  // 8 GiB per file
constexpr uint64_t MAX_DIR_ENTRIES = 1u << 20;          // per directory item

struct Super {
    uint64_t base = 0;        // absolute file offset of block 0 (partition start)
    uint64_t block_size = 0;
    uint64_t block_count = 0;
    uint32_t root_block = 0;
    uint16_t tree_height = 0;
};

// One leaf item, kept as a reference into the image (body read on demand).
struct Item {
    uint32_t dir_id = 0;
    uint32_t objectid = 0;
    uint64_t offset = 0;  // object byte-offset key (1-based for file bodies)
    IType type = IType::Other;
    bool v2 = false;
    uint16_t entry_count = 0;  // directory items only
    uint64_t body_off = 0;     // absolute file offset of the item body
    uint32_t body_len = 0;
};

struct Ctx {
    const Reader& r;
    Super sb;
    SafeRoot* root;  // null in the fuzz probe (parse-only, no writes)
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t nodes_seen = 0;
    size_t files_seen = 0;
    std::vector<Item> items{};
    // (dir_id,objectid) -> indices into `items`.
    std::unordered_map<uint64_t, std::vector<uint32_t>> by_object{};
    std::unordered_set<uint64_t> visited_blocks{};  // tree cycle guard
    std::set<uint64_t> stack{};                      // directory recursion cycle guard
};

std::optional<uint16_t> rd16(const Reader& r, uint64_t off) {
    return r.at<uint16_t>(static_cast<size_t>(off), Endian::Little);
}
std::optional<uint32_t> rd32(const Reader& r, uint64_t off) {
    return r.at<uint32_t>(static_cast<size_t>(off), Endian::Little);
}
std::optional<uint64_t> rd64(const Reader& r, uint64_t off) {
    return r.at<uint64_t>(static_cast<size_t>(off), Endian::Little);
}

uint64_t block_off(const Ctx& c, uint64_t blk) { return c.sb.base + blk * c.sb.block_size; }
uint64_t okey(uint32_t dir_id, uint32_t objectid) {
    return (uint64_t(dir_id) << 32) | objectid;
}

// Read the superblock fields at absolute offset `sbo`.
bool parse_super_at(const Reader& r, uint64_t sbo, Super& sb) {
    auto bcount = rd32(r, sbo + 0);
    auto rootb = rd32(r, sbo + 8);
    auto bsize = rd16(r, sbo + 44);
    auto height = rd16(r, sbo + 68);
    if (!bcount || !rootb || !bsize || !height) return false;
    uint64_t bs = *bsize;
    if ((bs & (bs - 1)) != 0 || bs < 512 || bs > 8192) return false;
    if (*bcount == 0 || *rootb == 0) return false;
    sb.block_size = bs;
    sb.block_count = *bcount;
    sb.root_block = *rootb;
    sb.tree_height = *height;
    return true;
}

// A root block is plausible if its block header has a sane level and item count.
bool root_block_ok(const Reader& r, const Super& sb) {
    const uint64_t bo = sb.base + uint64_t(sb.root_block) * sb.block_size;
    auto level = rd16(r, bo + 0);
    auto nr = rd16(r, bo + 2);
    if (!level || !nr) return false;
    if (*level < LEAF_LEVEL || *level > MAX_LEVEL) return false;
    // An internal node needs nr keys + nr+1 children; a leaf nr item headers.
    const uint64_t need_internal = BLKH_SIZE + uint64_t(*nr) * KEY_SIZE + (uint64_t(*nr) + 1) * DC_SIZE;
    const uint64_t need_leaf = BLKH_SIZE + uint64_t(*nr) * IH_SIZE;
    return need_internal <= sb.block_size || need_leaf <= sb.block_size;
}

// Decode one leaf item header at absolute offset `iho` into `it`. `block_base`
// is the containing leaf's absolute start, used to resolve ih_item_location.
bool decode_item(const Reader& r, uint64_t iho, uint64_t block_base, uint64_t block_size,
                 Item& it) {
    auto dir_id = rd32(r, iho + 0);
    auto objectid = rd32(r, iho + 4);
    auto ucnt = rd16(r, iho + 16);
    auto ilen = rd16(r, iho + 18);
    auto iloc = rd16(r, iho + 20);
    auto iver = rd16(r, iho + 22);
    if (!dir_id || !objectid || !ucnt || !ilen || !iloc || !iver) return false;

    it.dir_id = *dir_id;
    it.objectid = *objectid;
    it.v2 = (*iver != 0);
    it.entry_count = *ucnt;

    if (it.v2) {
        auto v = rd64(r, iho + 8);
        if (!v) return false;
        it.offset = *v & ((uint64_t(1) << 60) - 1);
        switch (static_cast<uint32_t>(*v >> 60)) {
            case 0: it.type = IType::SD; break;
            case 1: it.type = IType::Indirect; break;
            case 2: it.type = IType::Direct; break;
            case 3: it.type = IType::DirEntry; break;
            default: it.type = IType::Other; break;
        }
    } else {
        auto off = rd32(r, iho + 8);
        auto uniq = rd32(r, iho + 12);
        if (!off || !uniq) return false;
        it.offset = *off;
        switch (*uniq) {
            case V1_SD: it.type = IType::SD; break;
            case V1_DIRECT: it.type = IType::Direct; break;
            case V1_INDIRECT: it.type = IType::Indirect; break;
            case V1_DIRENTRY: it.type = IType::DirEntry; break;
            default: it.type = IType::Other; break;
        }
    }

    // Body must lie inside the block, past the header area.
    if (*iloc < BLKH_SIZE || uint64_t(*iloc) + *ilen > block_size) return false;
    it.body_off = block_base + *iloc;
    it.body_len = *ilen;
    return true;
}

// Depth-first walk of the S+ tree, collecting every leaf item into c.items.
void walk_tree(Ctx& c, uint64_t blk, size_t depth) {
    if (depth > MAX_LEVEL || c.nodes_seen++ > MAX_NODES) { c.truncated = true; return; }
    if (blk == 0 || blk >= c.sb.block_count) { c.truncated = true; return; }
    if (!c.visited_blocks.insert(blk).second) { c.truncated = true; return; }  // cycle

    const uint64_t bo = block_off(c, blk);
    auto level = rd16(c.r, bo + 0);
    auto nr = rd16(c.r, bo + 2);
    if (!level || !nr) { c.truncated = true; return; }
    if (*level < LEAF_LEVEL || *level > MAX_LEVEL) { c.truncated = true; return; }

    if (*level == LEAF_LEVEL) {
        // nr item headers, each IH_SIZE, starting after the block header.
        const uint64_t max_items = (c.sb.block_size - BLKH_SIZE) / IH_SIZE;
        uint64_t n = *nr;
        if (n > max_items) { n = max_items; c.truncated = true; }
        for (uint64_t i = 0; i < n; ++i) {
            if (c.items.size() >= MAX_ITEMS) { c.truncated = true; return; }
            Item it;
            if (!decode_item(c.r, bo + BLKH_SIZE + i * IH_SIZE, bo, c.sb.block_size, it)) {
                c.truncated = true;
                continue;
            }
            c.by_object[okey(it.dir_id, it.objectid)].push_back(
                static_cast<uint32_t>(c.items.size()));
            c.items.push_back(it);
        }
        return;
    }

    // Internal node: nr keys then nr+1 child pointers.
    const uint64_t children = bo + BLKH_SIZE + uint64_t(*nr) * KEY_SIZE;
    const uint64_t last = children + (uint64_t(*nr) + 1) * DC_SIZE;
    if (last > c.sb.block_size + bo) { c.truncated = true; return; }
    for (uint64_t j = 0; j <= *nr; ++j) {
        auto child = rd32(c.r, children + j * DC_SIZE);  // dc_block_number
        if (!child) { c.truncated = true; continue; }
        walk_tree(c, *child, depth + 1);
    }
}

// The stat-data item for an object, if present.
const Item* find_sd(Ctx& c, uint32_t dir_id, uint32_t objectid) {
    auto it = c.by_object.find(okey(dir_id, objectid));
    if (it == c.by_object.end()) return nullptr;
    for (uint32_t idx : it->second)
        if (c.items[idx].type == IType::SD) return &c.items[idx];
    return nullptr;
}

bool sd_mode_size(Ctx& c, const Item& sd, uint16_t& mode, uint64_t& size) {
    auto m = rd16(c.r, sd.body_off + 0);
    if (!m) return false;
    mode = *m;
    if (sd.v2) {
        if (sd.body_len < SD_V2_SIZE) return false;
        auto s = rd64(c.r, sd.body_off + 8);
        if (!s) return false;
        size = *s;
    } else {
        if (sd.body_len < SD_V1_SIZE) return false;
        auto s = rd32(c.r, sd.body_off + 8);
        if (!s) return false;
        size = *s;
    }
    return true;
}

// Reconstruct a regular file / symlink target for an object into `out` (capped).
void read_content(Ctx& c, uint32_t dir_id, uint32_t objectid, uint64_t size,
                  std::vector<uint8_t>& out) {
    if (size > MAX_FILE_BYTES) { size = MAX_FILE_BYTES; c.truncated = true; }
    // A file's bytes all come from blocks in the image, so a declared size larger
    // than the image is corrupt (or a huge sparse file); clamp to avoid honoring
    // it with a giant zero-filled allocation.
    if (size > c.r.size()) { size = c.r.size(); c.truncated = true; }
    out.assign(static_cast<size_t>(size), 0);
    auto found = c.by_object.find(okey(dir_id, objectid));
    if (found == c.by_object.end()) return;

    // Gather body items (direct tail + indirect block lists) in file order.
    std::vector<const Item*> bodies;
    for (uint32_t idx : found->second) {
        const Item& it = c.items[idx];
        if (it.type == IType::Direct || it.type == IType::Indirect) bodies.push_back(&it);
    }
    std::sort(bodies.begin(), bodies.end(),
              [](const Item* a, const Item* b) { return a->offset < b->offset; });

    const uint64_t bs = c.sb.block_size;
    for (const Item* it : bodies) {
        if (it->offset == 0) { c.truncated = true; continue; }  // body keys are 1-based
        const uint64_t pos = it->offset - 1;
        if (it->type == IType::Direct) {
            auto span = c.r.bytes(static_cast<size_t>(it->body_off), it->body_len);
            if (!span) { c.truncated = true; continue; }
            for (uint64_t k = 0; k < it->body_len && pos + k < size; ++k)
                out[static_cast<size_t>(pos + k)] = (*span)[static_cast<size_t>(k)];
        } else {  // Indirect: array of u32 unformatted-block numbers
            const uint64_t nptr = it->body_len / 4;
            for (uint64_t k = 0; k < nptr; ++k) {
                auto blk = rd32(c.r, it->body_off + k * 4);
                const uint64_t dst = pos + k * bs;
                if (dst >= size) break;
                const uint64_t want = std::min<uint64_t>(bs, size - dst);
                if (!blk || *blk == 0) continue;  // sparse hole -> leave zeros
                if (*blk >= c.sb.block_count) { c.truncated = true; continue; }
                auto span = c.r.bytes(static_cast<size_t>(block_off(c, *blk)),
                                      static_cast<size_t>(want));
                if (!span) { c.truncated = true; continue; }
                std::memcpy(out.data() + static_cast<size_t>(dst), span->data(),
                            static_cast<size_t>(want));
            }
        }
    }
}

struct Entry {
    std::string name;
    uint32_t dir_id;
    uint32_t objectid;
};

// Parse one directory item's packed entries into `out` (pure; no writes).
// deh array is at the item start; names are packed toward the item end. Entry
// i's name runs from deh[i].location to the next-higher boundary: deh[i-1]'s
// location for i>0, else the item length (deh[0] holds the highest location).
// All reads are bounded by body_len.
void collect_entries(Ctx& c, const Item& it, std::vector<Entry>& out) {
    uint64_t nent = it.entry_count;
    if (nent > MAX_DIR_ENTRIES) { nent = MAX_DIR_ENTRIES; c.truncated = true; }
    if (nent * DEH_SIZE > it.body_len) {
        nent = it.body_len / DEH_SIZE;
        c.truncated = true;
    }
    uint64_t prev_end = it.body_len;
    for (uint64_t i = 0; i < nent; ++i) {
        const uint64_t deh = it.body_off + i * DEH_SIZE;
        auto cdir = rd32(c.r, deh + 4);
        auto cobj = rd32(c.r, deh + 8);
        auto loc = rd16(c.r, deh + 12);
        if (!cdir || !cobj || !loc) { c.truncated = true; break; }
        const uint64_t name_start = *loc;
        const uint64_t name_end = prev_end;
        prev_end = name_start;  // the next (higher-index) entry ends where this one starts
        if (name_start < nent * DEH_SIZE || name_end > it.body_len || name_end <= name_start)
            continue;  // corrupt location
        auto span = c.r.bytes(static_cast<size_t>(it.body_off + name_start),
                              static_cast<size_t>(name_end - name_start));
        if (!span) { c.truncated = true; continue; }
        std::string name(reinterpret_cast<const char*>(span->data()), span->size());
        if (auto z = name.find('\0'); z != std::string::npos) name.resize(z);  // strip NUL pad
        out.push_back({std::move(name), *cdir, *cobj});
    }
}

// Every directory entry of an object, across all its directory items (key order).
std::vector<Entry> dir_entries(Ctx& c, uint32_t dir_id, uint32_t objectid) {
    std::vector<Entry> out;
    auto found = c.by_object.find(okey(dir_id, objectid));
    if (found == c.by_object.end()) return out;
    std::vector<const Item*> dir_items;
    for (uint32_t idx : found->second)
        if (c.items[idx].type == IType::DirEntry) dir_items.push_back(&c.items[idx]);
    std::sort(dir_items.begin(), dir_items.end(),
              [](const Item* a, const Item* b) { return a->offset < b->offset; });
    for (const Item* it : dir_items) collect_entries(c, *it, out);
    return out;
}

void walk_dir(Ctx& c, uint32_t dir_id, uint32_t objectid, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (c.files_seen++ > MAX_FILES) { c.truncated = true; return; }
    const uint64_t k = okey(dir_id, objectid);
    if (!c.stack.insert(k).second) return;  // directory cycle (corrupt image)

    for (const Entry& e : dir_entries(c, dir_id, objectid)) {
        const std::string& name = e.name;
        if (name.empty() || name == "." || name == "..") continue;
        if (name.find('/') != std::string::npos || name.find('\0') != std::string::npos) continue;
        const Item* sd = find_sd(c, e.dir_id, e.objectid);
        if (!sd) { c.truncated = true; continue; }
        uint16_t mode = 0;
        uint64_t size = 0;
        if (!sd_mode_size(c, *sd, mode, size)) { c.truncated = true; continue; }

        const std::string child_rel = rel.empty() ? name : rel + "/" + name;
        const std::string full = c.subdir + "/" + child_rel;
        const uint16_t type = mode & S_IFMT;

        if (type == S_IFDIR) {
            if (c.root && c.root->make_dir(full)) c.out.dirs++;
            walk_dir(c, e.dir_id, e.objectid, child_rel, depth + 1);
        } else if (type == S_IFLNK) {
            std::vector<uint8_t> buf;
            read_content(c, e.dir_id, e.objectid, std::min<uint64_t>(size, 4096), buf);
            std::string target(buf.begin(), buf.end());
            if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
            if (!target.empty() && c.root && c.root->make_symlink(full, target)) c.out.symlinks++;
        } else if (type == S_IFREG) {
            std::vector<uint8_t> data;
            read_content(c, e.dir_id, e.objectid, size, data);
            if (c.root && c.root->write_file(full, data, mode & 0777)) {
                c.out.files++;
                c.out.bytes += data.size();
            } else if (c.root) {
                c.out.warnings.push_back("write failed: " + child_rel);
            }
        }
        // Other types (fifo/chr/blk/sock): skipped.
    }
    c.stack.erase(k);
}

// Recover the partition base for a superblock at `sb_off`, filling sb.base.
// Returns false if neither the 3.6 nor 3.5 placement yields a sane root block.
bool locate_base(const Reader& r, uint64_t sb_off, Super& sb) {
    for (uint64_t disk_off : {DISK_OFFSET_36, DISK_OFFSET_35}) {
        if (sb_off < disk_off) continue;
        sb.base = sb_off - disk_off;
        if (root_block_ok(r, sb)) return true;
    }
    return false;
}

}  // namespace

bool extract_reiserfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                      Extracted& out) {
    out.offset = f.offset;
    out.type = "reiserfs";
    out.root = subdir;

    Super sb;
    if (!parse_super_at(r, f.offset, sb)) {
        out.status = "error:bad-superblock";
        return true;
    }
    // The superblock sits at a fixed offset inside the partition; the tree's
    // block numbers count from the partition start, so recover that base. The
    // 3.6 superblock is 64 KiB in, the 3.5 one 8 KiB in. Pick the base whose
    // root block has a sane header (handles an image that is a bare partition
    // starting at 0, or one carved with the superblock at its real offset).
    if (!locate_base(r, f.offset, sb)) {
        out.status = "error:root-block";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    Ctx c{r, sb, &root, subdir, out};
    walk_tree(c, sb.root_block, 0);
    walk_dir(c, ROOT_PARENT_OBJECTID, ROOT_OBJECTID, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

// Parse-only driver for fuzzing: recover the base from a superblock at `sb_off`,
// walk the whole S+ tree, then exercise the byte-sensitive paths on every object
// (content reconstruction and directory-entry parsing) with no SafeRoot writes.
// Returns the number of items collected (unused; keeps the call from being
// optimized away). All reads are bounds-checked, so any input is safe.
size_t reiserfs_probe(const Reader& r, size_t sb_off) {
    Super sb;
    if (!parse_super_at(r, sb_off, sb)) return 0;
    if (!locate_base(r, sb_off, sb)) return 0;
    Extracted out;
    Ctx c{r, sb, nullptr, "", out};
    walk_tree(c, sb.root_block, 0);
    uint64_t budget = 64u << 20;  // bound total content read so fuzzing stays fast
    for (const auto& kv : c.by_object) {
        const uint32_t dir_id = static_cast<uint32_t>(kv.first >> 32);
        const uint32_t objectid = static_cast<uint32_t>(kv.first & 0xffffffff);
        if (const Item* sd = find_sd(c, dir_id, objectid)) {
            uint16_t mode = 0;
            uint64_t size = 0;
            if (sd_mode_size(c, *sd, mode, size) && budget > 0) {
                std::vector<uint8_t> buf;
                read_content(c, dir_id, objectid, std::min<uint64_t>(size, budget), buf);
                budget -= std::min<uint64_t>(buf.size(), budget);
            }
        }
        auto ents = dir_entries(c, dir_id, objectid);
        (void)ents;
    }
    return c.items.size();
}

}  // namespace ft

// littlefs.cpp — LittleFS parser (identify + extract). See littlefs.hpp and
// docs/littlefs-ondisk-notes.md. Clean reimplementation of the littlefs
// (BSD-3-Clause) on-disk commit/CTZ algorithm against moria's Reader.
#include "littlefs_parse.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <set>
#include <vector>

#include "crc32.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint32_t LFS_NULL = 0xFFFFFFFFu;

// bit-twiddle helpers (match the prototype / lfs_util)
int lfs_ctz(uint32_t x) {
    if (x == 0) return 32;
    int n = 0;
    while (!(x & 1)) { x >>= 1; ++n; }
    return n;
}
int lfs_popc(uint32_t x) {
    int n = 0;
    while (x) { n += x & 1; x >>= 1; }
    return n;
}

// tag field extractors (tag is the decoded, un-XORed 32-bit value)
inline uint32_t tag_type(uint32_t t) { return (t >> 20) & 0x7ff; }
inline uint32_t tag_id(uint32_t t) { return (t >> 10) & 0x3ff; }
inline uint32_t tag_size(uint32_t t) { return t & 0x3ff; }
inline bool tag_invalid(uint32_t t) { return (t & 0x80000000u) != 0; }
inline uint32_t tag_dsize(uint32_t t) {
    uint32_t sz = tag_size(t);
    return 4 + (sz == 0x3ff ? 0 : sz);
}

uint32_t u32le(const Reader& r, size_t off) {
    auto v = r.at<uint32_t>(off, Endian::Little);
    return v ? *v : 0;
}
uint32_t u32be(const Reader& r, size_t off) {
    auto v = r.at<uint32_t>(off, Endian::Big);
    return v ? *v : 0;
}

// One directory entry rebuilt from the tags of a metadata pair.
struct Entry {
    bool has_name = false;
    uint8_t ftype = 0;      // 1 = reg, 2 = dir
    std::string name;
    enum { NONE, INLINE, CTZ, DIR } kind = NONE;
    std::vector<uint8_t> inln;
    uint32_t ctz_head = 0, ctz_size = 0;
    uint32_t dir0 = LFS_NULL, dir1 = LFS_NULL;
};

// A parsed metadata directory (one live pair): its id→entry map + tail pointer.
struct Mdir {
    bool ok = false;
    bool crc_fail = false;
    uint32_t rev = 0;
    std::map<int, Entry> ids;
    bool has_tail = false;
    bool tail_hard = false;  // 0x601 hardtail = split continuation of THIS dir
    uint32_t tail0 = LFS_NULL, tail1 = LFS_NULL;
};

// Shift entry ids >= `at` by `delta` (CREATE/DELETE renumber the id space).
void shift_ids(std::map<int, Entry>& ids, int at, int delta) {
    std::map<int, Entry> out;
    for (auto& [i, e] : ids) out[i >= at ? i + delta : i] = std::move(e);
    ids.swap(out);
}

void apply_tag(std::map<int, Entry>& ids, uint32_t type, uint32_t id,
               std::span<const uint8_t> data) {
    if (type == 0x401) {  // CREATE at id: make room
        shift_ids(ids, static_cast<int>(id), +1);
        ids[static_cast<int>(id)] = Entry{};
        return;
    }
    if (type == 0x4ff) {  // DELETE id: drop + shift down
        ids.erase(static_cast<int>(id));
        shift_ids(ids, static_cast<int>(id) + 1, -1);
        return;
    }
    Entry& e = ids[static_cast<int>(id)];
    uint32_t t1 = type >> 8;
    if (t1 == 0) {  // NAME tag: chunk = file type
        e.has_name = true;
        e.ftype = static_cast<uint8_t>(type & 0xff);
        e.name.assign(reinterpret_cast<const char*>(data.data()), data.size());
    } else if (type == 0x201) {
        e.kind = Entry::INLINE;
        e.inln.assign(data.begin(), data.end());
    } else if (type == 0x202 && data.size() >= 8) {
        e.kind = Entry::CTZ;
        std::memcpy(&e.ctz_head, data.data(), 4);
        std::memcpy(&e.ctz_size, data.data() + 4, 4);
    } else if (type == 0x200 && data.size() >= 8) {
        e.kind = Entry::DIR;
        std::memcpy(&e.dir0, data.data(), 4);
        std::memcpy(&e.dir1, data.data() + 4, 4);
    }
}

// Faithful lfs_dir_fetch of one metadata block: apply every CRC-valid commit.
Mdir fetch_block(const Reader& r, uint32_t block, uint32_t bs, size_t origin) {
    Mdir md;
    if (block == LFS_NULL) return md;
    const size_t base = origin + static_cast<size_t>(block) * bs;
    if (!r.bytes(base, bs)) return md;  // block not wholly in range
    md.rev = u32le(r, base);

    size_t off = 0;
    uint32_t ptag = 0xFFFFFFFFu;
    std::vector<uint8_t> region;  // bytes CRC'd for the current commit
    region.reserve(bs);
    { auto rb = r.bytes(base, 4); region.insert(region.end(), rb->begin(), rb->end()); }

    std::map<int, Entry> pending;
    bool got = false;
    uint32_t ttail0 = LFS_NULL, ttail1 = LFS_NULL;
    bool thas = false, thard = false, committed_tail = false, committed_hard = false;
    uint32_t ctail0 = LFS_NULL, ctail1 = LFS_NULL;

    while (true) {
        off += tag_dsize(ptag);
        if (off + 4 > bs) break;
        uint32_t raw = u32be(r, base + off);
        { auto rb = r.bytes(base + off, 4); region.insert(region.end(), rb->begin(), rb->end()); }
        uint32_t tag = raw ^ ptag;
        if (tag_invalid(tag)) break;
        uint32_t type = tag_type(tag), id = tag_id(tag), sz = tag_size(tag);
        uint32_t t1 = type >> 8;

        if (t1 == 5 && type != 0x5ff) {  // CCRC — end of a commit
            uint32_t dcrc = u32le(r, base + off + 4);
            if (crc32_raw(0xFFFFFFFFu, region) != dcrc) { md.crc_fail = true; break; }
            md.ids = pending;   // commit accepted
            got = true;
            committed_tail = thas; committed_hard = thard; ctail0 = ttail0; ctail1 = ttail1;
            ptag = tag ^ ((type & 1) << 31);  // parity carries the valid bit
            region.clear();
            continue;
        }

        uint32_t dlen = (sz == 0x3ff) ? 0 : sz;
        auto db = r.bytes(base + off + 4, dlen);
        if (!db) break;
        region.insert(region.end(), db->begin(), db->end());
        if (type != 0x5ff) {  // apply everything except FCRC data
            if (type >= 0x600 && type <= 0x6ff && dlen >= 8) {
                thas = true;
                thard = (type == 0x601);  // hardtail = same-dir split continuation
                std::memcpy(&ttail0, db->data(), 4);
                std::memcpy(&ttail1, db->data() + 4, 4);
            }
            apply_tag(pending, type, id, *db);
        }
        ptag = tag;
    }

    if (!got) return md;
    md.ok = true;
    md.has_tail = committed_tail;
    md.tail_hard = committed_hard;
    md.tail0 = ctail0;
    md.tail1 = ctail1;
    return md;
}

// The live copy of a metadata pair = the CRC-valid block with the higher rev.
Mdir fetch_pair(const Reader& r, uint32_t b0, uint32_t b1, uint32_t bs, size_t origin) {
    Mdir a = fetch_block(r, b0, bs, origin);
    Mdir b = fetch_block(r, b1, bs, origin);
    if (a.ok && b.ok) return (b.rev > a.rev) ? b : a;  // (rev wraps; > is the lfs rule)
    if (a.ok) return a;
    if (b.ok) return b;
    Mdir bad;
    bad.crc_fail = a.crc_fail || b.crc_fail;
    return bad;
}

// ---- CTZ skip-list ---------------------------------------------------------
int ctz_index(uint32_t x, uint32_t bs) {
    uint32_t b = bs - 8;
    uint32_t i = x / b;
    if (i == 0) return 0;
    i = (x - 4 * (lfs_popc(i - 1) + 2)) / b;
    return static_cast<int>(i);
}

// Read a CTZ file's bytes. Bounded by block_count (no cycles / runaway).
std::vector<uint8_t> ctz_read(const Reader& r, const LfsSuper& s, uint32_t head,
                              uint32_t size, size_t origin, bool& ok) {
    ok = true;
    std::vector<uint8_t> out;
    if (size == 0) return out;
    const uint32_t bs = s.block_size;
    int top = ctz_index(size - 1, bs);
    if (top < 0 || static_cast<uint32_t>(top) >= s.block_count) { ok = false; return out; }

    // Collect (index -> block) head-first, like lfs_ctz_traverse.
    std::vector<uint32_t> by_index(static_cast<size_t>(top) + 1, LFS_NULL);
    uint32_t h = head;
    int idx = top;
    size_t guard = 0;
    while (true) {
        if (h >= s.block_count || idx < 0) { ok = false; return out; }
        by_index[idx] = h;
        if (idx == 0) break;
        int count = 2 - (idx & 1);
        auto p0 = r.at<uint32_t>(origin + static_cast<size_t>(h) * bs, Endian::Little);
        if (!p0) { ok = false; return out; }
        if (count == 2) {
            auto p1 = r.at<uint32_t>(origin + static_cast<size_t>(h) * bs + 4, Endian::Little);
            if (!p1) { ok = false; return out; }
            if (idx - 1 >= 0) by_index[idx - 1] = *p0;
            h = *p1;
        } else {
            h = *p0;
        }
        idx -= count;
        if (++guard > s.block_count + 4) { ok = false; return out; }
    }

    out.reserve(size);
    for (int i = 0; i <= top && out.size() < size; ++i) {
        uint32_t blk = by_index[i];
        if (blk >= s.block_count) { ok = false; break; }
        uint32_t nptr = (i > 0) ? static_cast<uint32_t>(lfs_ctz(i) + 1) : 0;
        uint32_t doff = 4 * nptr;
        if (doff >= bs) { ok = false; break; }
        size_t need = size - out.size();
        size_t avail = bs - doff;
        auto db = r.bytes(origin + static_cast<size_t>(blk) * bs + doff, std::min<size_t>(avail, need));
        if (!db) { ok = false; break; }
        out.insert(out.end(), db->begin(), db->end());
    }
    if (out.size() > size) out.resize(size);
    return out;
}

}  // namespace

// Read block 0's id-0 superblock entry from a fetched mdir (magic name + inline
// geometry). Fills geometry into `s`; returns false if it isn't a superblock.
static bool read_super_entry(const Mdir& m, LfsSuper& s) {
    if (!m.ok) return false;
    auto it = m.ids.find(0);
    if (it == m.ids.end()) return false;
    const Entry& e = it->second;
    if (!e.has_name || e.name != "littlefs" || e.kind != Entry::INLINE || e.inln.size() < 24)
        return false;
    std::memcpy(&s.version, e.inln.data() + 0, 4);
    std::memcpy(&s.block_size, e.inln.data() + 4, 4);
    std::memcpy(&s.block_count, e.inln.data() + 8, 4);
    std::memcpy(&s.name_max, e.inln.data() + 12, 4);
    std::memcpy(&s.file_max, e.inln.data() + 16, 4);
    std::memcpy(&s.attr_max, e.inln.data() + 20, 4);
    return true;
}

LfsSuper lfs_read_super(const Reader& r, size_t origin) {
    LfsSuper s;
    // The magic "littlefs" sits at byte 8 of block 0 (the superblock name entry).
    auto magic = r.bytes(origin + 8, 8);
    if (!magic || std::memcmp(magic->data(), "littlefs", 8) != 0) return s;

    // Provisional fetch: the superblock is the FIRST commit and fits in any real
    // block size, so a large provisional block size recovers its inline-struct
    // geometry (id 0's inline struct is immutable across commits).
    const size_t avail = (r.size() > origin) ? r.size() - origin : 0;
    uint32_t prov = static_cast<uint32_t>(std::min<size_t>(avail, 8192));
    if (prov < 128) return s;
    LfsSuper prov_s;
    if (!read_super_entry(fetch_block(r, 0, prov, origin), prov_s)) return s;

    uint32_t bsz = prov_s.block_size;
    if (bsz < 128 || bsz > (1u << 20) || (bsz & (bsz - 1)) || prov_s.block_count == 0)
        return s;

    // Authoritative fetch with the declared block size: the CRC must verify at the
    // real geometry (block 1 may be out of a partially-mapped region — block 0
    // alone is enough for identify).
    Mdir a = fetch_block(r, 0, bsz, origin);
    if (!read_super_entry(a, s)) return s;
    s.ok = true;
    s.crc_verified = true;  // fetch_block returns ok only on a CRC-valid commit
    s.origin = origin;
    return s;
}

bool lfs_extract(const Reader& r, const LfsSuper& s, SafeRoot& root,
                 const std::string& subdir, LfsStats& st) {
    if (!s.ok || s.block_size == 0 || s.block_count == 0) return false;
    if (!root.make_dir(subdir)) return false;

    constexpr size_t kMaxFiles = 200000, kMaxDirs = 100000, kMaxDepth = 100;
    constexpr uint64_t kMaxBytes = uint64_t(4) << 30;

    std::set<uint64_t> seen;  // visited metadata pairs (b0<<32|b1)
    // Iterative walk: (b0, b1, path, depth). Follows dir structs (into children)
    // and the mdir tail thread; dedups pairs.
    struct Frame { uint32_t b0, b1; std::string path; size_t depth; };
    std::vector<Frame> stack{{0, 1, subdir, 0}};

    while (!stack.empty()) {
        Frame f = stack.back();
        stack.pop_back();
        if (f.depth > kMaxDepth) { st.truncated = true; continue; }
        uint64_t key = (uint64_t(f.b0) << 32) | f.b1;
        if (!seen.insert(key).second) continue;

        Mdir md = fetch_pair(r, f.b0, f.b1, s.block_size, s.origin);
        if (!md.ok) { if (md.crc_fail) st.crc_fail = true; continue; }

        for (auto& [id, e] : md.ids) {
            if (!e.has_name || e.kind == Entry::NONE) continue;
            // Skip the superblock's own self-entry (id 0 "littlefs" geometry).
            if (f.b0 == 0 && f.b1 == 1 && e.name == "littlefs" && e.kind == Entry::INLINE)
                continue;
            if (e.name.empty() || e.name.find('/') != std::string::npos ||
                e.name == "." || e.name == "..")
                continue;
            std::string child = f.path + "/" + e.name;
            if (e.kind == Entry::DIR) {
                if (st.dirs >= kMaxDirs) { st.truncated = true; continue; }
                if (root.make_dir(child)) st.dirs++;
                stack.push_back({e.dir0, e.dir1, child, f.depth + 1});
            } else if (e.kind == Entry::INLINE) {
                if (st.files >= kMaxFiles || st.bytes >= kMaxBytes) { st.truncated = true; continue; }
                if (root.write_file(child, e.inln, 0644)) { st.files++; st.bytes += e.inln.size(); }
            } else if (e.kind == Entry::CTZ) {
                if (st.files >= kMaxFiles || st.bytes >= kMaxBytes) { st.truncated = true; continue; }
                if (e.ctz_size > s.file_max && s.file_max) { st.truncated = true; continue; }
                bool ok = false;
                std::vector<uint8_t> data = ctz_read(r, s, e.ctz_head, e.ctz_size, s.origin, ok);
                if (!ok) { st.crc_fail = true; continue; }
                if (root.write_file(child, data, 0644)) { st.files++; st.bytes += data.size(); }
            }
        }
        // Follow only a HARDTAIL: it continues THIS directory's id space in
        // another mdir (a split). A softtail threads to a different directory,
        // which is already reached via its parent's dir entry, so following it
        // would relabel those files under the wrong path.
        if (md.has_tail && md.tail_hard && md.tail0 != LFS_NULL)
            stack.push_back({md.tail0, md.tail1, f.path, f.depth});
    }
    return true;
}

}  // namespace ft

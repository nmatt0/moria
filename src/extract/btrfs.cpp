// btrfs.cpp — btrfs extraction. See btrfs.hpp. All fields little-endian.
//
//  - Superblock @ base+0x10000: magic '_BHRfS_M' @64, root(logical) @80,
//    chunk_root @88, total_bytes @112, sectorsize @144, nodesize @148,
//    sys_chunk_array_size @160, root_level @198, chunk_root_level @199,
//    sys_chunk_array @811.
//  - Chunk map: the sys_chunk_array holds (disk_key, chunk) pairs that map the
//    chunk-tree logical range; walking the chunk tree adds the rest. A chunk maps
//    logical [key.offset, +length) to the first stripe's physical offset.
//  - Tree node: header {nritems @96 (u32), level @100 (u8)} of 101 bytes; an
//    internal node has nritems key_ptrs (key 17 + blockptr @17 + gen, 33 bytes);
//    a leaf has nritems items (key 17 + offset @17 + size @21, 25 bytes) whose
//    data sits at 101+offset.
//  - FS tree items: INODE_ITEM (mode @52, size @16), DIR_INDEX (location key +
//    name), EXTENT_DATA (file_extent_item: type @20, compression @16, inline data
//    @21, else disk_bytenr @21 / disk_num_bytes @29 / offset @37 / num_bytes @45).
#include "extract/btrfs.hpp"

#include "byteorder.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "extract/decompress.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint64_t SB_OFFSET = 0x10000;
constexpr uint32_t HEADER_SIZE = 101;
constexpr uint32_t KEY_PTR_SIZE = 33;
constexpr uint32_t ITEM_SIZE = 25;

// key types
constexpr uint8_t INODE_ITEM_KEY = 1;
constexpr uint8_t DIR_INDEX_KEY = 96;
constexpr uint8_t EXTENT_DATA_KEY = 108;
constexpr uint8_t ROOT_ITEM_KEY = 132;
constexpr uint8_t CHUNK_ITEM_KEY = 228;

// objectids
constexpr uint64_t FS_TREE_OBJECTID = 5;
constexpr uint64_t FIRST_FREE_OBJECTID = 256;  // the FS tree's root directory

// file_extent_item.type
constexpr uint8_t EXTENT_INLINE = 0;
constexpr uint8_t EXTENT_REG = 1;
constexpr uint8_t EXTENT_PREALLOC = 2;

// compression
constexpr uint8_t COMPRESS_NONE = 0, COMPRESS_ZLIB = 1, COMPRESS_LZO = 2, COMPRESS_ZSTD = 3;

// dir_item.type (BTRFS_FT_*)
constexpr uint8_t FT_REG = 1, FT_DIR = 2, FT_SYMLINK = 7;

constexpr uint16_t S_IFMT_ = 0170000;
constexpr uint16_t S_IFDIR_ = 0040000;
constexpr uint16_t S_IFREG_ = 0100000;
constexpr uint16_t S_IFLNK_ = 0120000;

constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;
constexpr size_t MAX_NODES = 2000000;
constexpr size_t MAX_DEPTH = 64;

std::optional<uint32_t> u32(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Little); }
std::optional<uint64_t> u64(const Reader& r, uint64_t o) { return r.at<uint64_t>(o, Endian::Little); }

// little-endian reads out of an in-memory span
// btrfs is little-endian on disk; thin wrappers over the shared loads.
inline uint16_t g16(std::span<const uint8_t> b, size_t o) { return load_le16(b, o); }
inline uint32_t g32(std::span<const uint8_t> b, size_t o) { return load_le32(b, o); }
inline uint64_t g64(std::span<const uint8_t> b, size_t o) { return load_le64(b, o); }

struct Stripe {
    uint64_t devid = 0;
    uint64_t offset = 0;
};

struct Chunk {
    uint64_t logical = 0;
    uint64_t length = 0;
    uint64_t type = 0;               // block-group flags (RAID profile)
    std::vector<Stripe> stripes{};
};

// RAID profile bits in a chunk's type. The striped ones (RAID0/10/5/6) interleave
// a chunk's data across devices, so a single-device image can't map them linearly.
constexpr uint64_t BG_RAID0 = 1ULL << 3;
constexpr uint64_t BG_RAID10 = 1ULL << 6;
constexpr uint64_t BG_RAID5 = 1ULL << 7;
constexpr uint64_t BG_RAID6 = 1ULL << 8;
constexpr uint64_t BG_STRIPED = BG_RAID0 | BG_RAID10 | BG_RAID5 | BG_RAID6;

struct Inode {
    uint16_t mode = 0;
    uint64_t size = 0;
};

struct DirEnt {
    std::string name;
    uint64_t child = 0;    // child inode number, or (is_subvol) the subvolume id
    uint8_t ftype = 0;
    bool is_subvol = false;  // location.type == ROOT_ITEM_KEY: a nested subvolume
};

// One EXTENT_DATA record (already copied out of the leaf).
struct FExt {
    uint64_t file_off = 0;   // key.offset
    uint8_t type = 0;
    uint8_t compression = 0;
    uint64_t ram_bytes = 0;
    uint64_t disk_bytenr = 0;
    uint64_t disk_num_bytes = 0;
    uint64_t offset = 0;
    uint64_t num_bytes = 0;
    std::vector<uint8_t> inline_data;  // for EXTENT_INLINE
};

// The collected items of one subvolume's FS tree (each subvolume has its own
// inode-number namespace, so these cannot be shared across subvolumes).
struct Subvol {
    std::map<uint64_t, Inode> inodes{};
    std::map<uint64_t, std::vector<DirEnt>> children{};  // parent -> entries
    std::map<uint64_t, std::vector<FExt>> extents{};     // inode -> file extents
};

struct Ctx {
    const Reader& r;
    uint64_t base;
    uint32_t nodesize = 16384;
    uint32_t sectorsize = 4096;
    uint64_t image_devid = 0;  // this image's device id (superblock dev_item.devid)
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    std::vector<Chunk> chunks{};
    std::map<uint64_t, uint64_t> root_items{};  // subvolume id -> FS-tree root bytenr
    std::set<uint64_t> subvols_done{};          // subvolume-recursion guard
    std::set<uint64_t> walked{};                // node cycle guard (per tree walk)
    std::set<uint64_t> tree_stack{};            // path cycle guard
    size_t nodes = 0;
    bool truncated = false;
};

// Map a logical address to an absolute byte offset in this image, or nullopt.
// For single/mirrored profiles (single, DUP, RAID1/1c3/1c4) the chunk has a
// contiguous copy on each device; pick the stripe on THIS device. Striped
// profiles (RAID0/10/5/6) interleave across devices and can't be mapped from a
// single image, so they (and chunks with no stripe on this device) return nullopt.
std::optional<uint64_t> map_logical(Ctx& c, uint64_t logical) {
    for (const Chunk& ch : c.chunks) {
        if (logical < ch.logical || logical >= ch.logical + ch.length) continue;
        if (ch.type & BG_STRIPED) return std::nullopt;
        for (const Stripe& s : ch.stripes) {
            if (s.devid == c.image_devid || c.image_devid == 0)
                return c.base + s.offset + (logical - ch.logical);
        }
        return std::nullopt;  // no stripe on this device (data lives elsewhere)
    }
    return std::nullopt;
}

// Read a whole tree node (nodesize bytes) at a logical address.
std::optional<std::vector<uint8_t>> read_node(Ctx& c, uint64_t logical) {
    auto phys = map_logical(c, logical);
    if (!phys) return std::nullopt;
    auto b = c.r.bytes(static_cast<size_t>(*phys), c.nodesize);
    if (!b) return std::nullopt;
    return std::vector<uint8_t>(b->begin(), b->end());
}

// Read `len` bytes at a logical address (for on-disk data extents).
std::optional<std::vector<uint8_t>> read_logical(Ctx& c, uint64_t logical, uint64_t len) {
    auto phys = map_logical(c, logical);
    if (!phys) return std::nullopt;
    auto b = c.r.bytes(static_cast<size_t>(*phys), static_cast<size_t>(len));
    if (!b) return std::nullopt;
    return std::vector<uint8_t>(b->begin(), b->end());
}

// Walk a btree from `logical`, invoking `cb(objectid, type, key_offset, item_data)`
// for every leaf item.
template <typename F>
void walk_tree(Ctx& c, uint64_t logical, size_t depth, F&& cb) {
    if (depth > MAX_DEPTH || ++c.nodes > MAX_NODES) { c.truncated = true; return; }
    if (!c.walked.insert(logical).second) return;
    auto node = read_node(c, logical);
    if (!node) { c.truncated = true; return; }
    std::span<const uint8_t> b = *node;
    if (b.size() < HEADER_SIZE) { c.truncated = true; return; }
    const uint32_t nritems = g32(b, 96);
    const uint8_t level = b[100];
    if (level == 0) {  // leaf
        for (uint32_t i = 0; i < nritems; ++i) {
            const size_t ip = HEADER_SIZE + size_t(i) * ITEM_SIZE;
            if (ip + ITEM_SIZE > b.size()) { c.truncated = true; break; }
            const uint64_t objectid = g64(b, ip);
            const uint8_t type = b[ip + 8];
            const uint64_t key_off = g64(b, ip + 9);
            const uint32_t data_off = g32(b, ip + 17);
            const uint32_t data_size = g32(b, ip + 21);
            const size_t dp = HEADER_SIZE + data_off;
            if (dp + data_size > b.size()) { c.truncated = true; continue; }
            cb(objectid, type, key_off, b.subspan(dp, data_size));
        }
    } else {  // internal node
        for (uint32_t i = 0; i < nritems; ++i) {
            const size_t kp = HEADER_SIZE + size_t(i) * KEY_PTR_SIZE;
            if (kp + KEY_PTR_SIZE > b.size()) { c.truncated = true; break; }
            const uint64_t blockptr = g64(b, kp + 17);
            walk_tree(c, blockptr, depth + 1, cb);
        }
    }
}

// Parse one btrfs_chunk (at `p` in span `b`) into the chunk map. btrfs_chunk:
// length@0, owner@8, stripe_len@16, type@24, io_align@32, io_width@36,
// sector_size@40, num_stripes@44, sub_stripes@46, then stripes (32 bytes each:
// devid@0, offset@8, dev_uuid@16) from @48.
void add_chunk(Ctx& c, uint64_t logical, std::span<const uint8_t> b, size_t p) {
    if (p + 48 > b.size()) return;
    Chunk ch;
    ch.logical = logical;
    ch.length = g64(b, p);
    ch.type = g64(b, p + 24);
    const uint16_t num_stripes = g16(b, p + 44);
    for (uint16_t i = 0; i < num_stripes; ++i) {
        const size_t sp = p + 48 + size_t(i) * 32;
        if (sp + 16 > b.size()) break;
        ch.stripes.push_back({g64(b, sp), g64(b, sp + 8)});
    }
    if (ch.length && !ch.stripes.empty()) c.chunks.push_back(std::move(ch));
}

// Bootstrap the chunk map from the superblock's sys_chunk_array: a packed run of
// (disk_key, btrfs_chunk) pairs.
void parse_sys_chunk_array(Ctx& c, std::span<const uint8_t> arr) {
    size_t p = 0;
    while (p + 17 + 48 <= arr.size()) {
        // disk_key: objectid(8), type(8? no -> 1 byte), offset(8) = 17 bytes
        const uint8_t ktype = arr[p + 8];
        const uint64_t logical = g64(arr, p + 9);
        p += 17;
        if (ktype != CHUNK_ITEM_KEY) break;
        const uint16_t num_stripes = g16(arr, p + 44);
        add_chunk(c, logical, arr, p);
        // advance past the chunk header + its stripes
        p += 48 + size_t(num_stripes ? num_stripes - 1 : 0) * 32;
        if (num_stripes == 0) break;
    }
}

void collect_fs_item(Ctx& c, Subvol& sv, uint64_t objectid, uint8_t type, uint64_t key_off,
                     std::span<const uint8_t> data);

// Walk one subvolume's FS tree, collecting inodes, directory entries, and file
// extents into `sv`.
void walk_fs_tree(Ctx& c, uint64_t logical, Subvol& sv) {
    c.walked.clear();
    walk_tree(c, logical, 0, [&](uint64_t oid, uint8_t type, uint64_t koff,
                                 std::span<const uint8_t> data) {
        collect_fs_item(c, sv, oid, type, koff, data);
    });
}

void collect_fs_item(Ctx& c, Subvol& sv, uint64_t objectid, uint8_t type, uint64_t key_off,
                     std::span<const uint8_t> data) {
    (void)c;
    if (type == INODE_ITEM_KEY) {
        if (data.size() < 56) return;
        Inode n;
        n.size = g64(data, 16);
        n.mode = static_cast<uint16_t>(g32(data, 52));
        sv.inodes[objectid] = n;
    } else if (type == DIR_INDEX_KEY) {
        // one btrfs_dir_item: location(17), transid(8), data_len(2)@25, name_len(2)@27,
        // ftype(1)@29, name@30.
        if (data.size() < 30) return;
        const uint64_t child = g64(data, 0);       // location.objectid
        const uint8_t loc_type = data[8];           // location.type
        const uint16_t name_len = g16(data, 27);
        const uint8_t ftype = data[29];
        // INODE_ITEM_KEY => an ordinary entry; ROOT_ITEM_KEY => a nested subvolume
        // (child = the subvolume id, resolved to its tree at reconstruction time).
        if (loc_type != INODE_ITEM_KEY && loc_type != ROOT_ITEM_KEY) return;
        if (name_len == 0 || size_t(30) + name_len > data.size()) return;
        DirEnt e;
        e.name.assign(reinterpret_cast<const char*>(data.data() + 30), name_len);
        e.child = child;
        e.ftype = ftype;
        e.is_subvol = loc_type == ROOT_ITEM_KEY;
        if (e.name == "." || e.name == ".." || e.name.find('/') != std::string::npos ||
            e.name.find('\0') != std::string::npos)
            return;
        sv.children[objectid].push_back(std::move(e));
    } else if (type == EXTENT_DATA_KEY) {
        if (data.size() < 21) return;
        FExt e;
        e.file_off = key_off;
        e.ram_bytes = g64(data, 8);
        e.compression = data[16];
        e.type = data[20];
        if (e.type == EXTENT_INLINE) {
            e.inline_data.assign(data.begin() + 21, data.end());
        } else {
            if (data.size() < 53) return;
            e.disk_bytenr = g64(data, 21);
            e.disk_num_bytes = g64(data, 29);
            e.offset = g64(data, 37);
            e.num_bytes = g64(data, 45);
        }
        sv.extents[objectid].push_back(std::move(e));
    }
}

// Decode a btrfs LZO extent: a 4-byte total-length header, then segments each of
// a 4-byte compressed-length header + an lzo1x block that decodes to one page. A
// segment header never straddles a page (4 KiB) boundary in the input; if fewer
// than 4 bytes remain in a page after a segment, the writer padded to the next.
std::optional<std::vector<uint8_t>> decode_btrfs_lzo(std::span<const uint8_t> src,
                                                     uint64_t out_len) {
    constexpr size_t PAGE = 4096, LZO_LEN = 4;
    if (src.size() < LZO_LEN) return std::nullopt;
    uint64_t tot_len = std::min<uint64_t>(g32(src, 0), src.size());
    std::vector<uint8_t> out;
    out.reserve(static_cast<size_t>(out_len));
    size_t in_off = LZO_LEN;
    uint64_t tot_in = LZO_LEN;
    while (tot_in < tot_len && out.size() < out_len) {
        if (in_off + LZO_LEN > src.size()) break;
        const uint32_t seg_len = g32(src, in_off);
        in_off += LZO_LEN;
        tot_in += LZO_LEN;
        if (seg_len == 0 || in_off + seg_len > src.size()) break;
        // Each segment decodes to a full page (padded); truncate the whole file
        // to out_len at the end.
        auto seg = decompress(Compressor::Lzo, src.subspan(in_off, seg_len), PAGE);
        if (!seg) break;
        out.insert(out.end(), seg->begin(), seg->end());
        in_off += seg_len;
        tot_in += seg_len;
        // A segment header must not straddle a page; skip any sub-header remainder.
        const size_t page_left = PAGE - (in_off % PAGE);
        if (page_left < LZO_LEN) {
            in_off += page_left;
            tot_in += page_left;
        }
    }
    out.resize(static_cast<size_t>(out_len), 0);
    return out;
}

// Decompress an extent's bytes per btrfs compression type to `out_len` bytes.
std::optional<std::vector<uint8_t>> decode_extent(uint8_t comp, std::span<const uint8_t> src,
                                                  uint64_t out_len) {
    switch (comp) {
        case COMPRESS_NONE: {
            std::vector<uint8_t> v(src.begin(),
                                   src.begin() + std::min<size_t>(src.size(), out_len));
            v.resize(static_cast<size_t>(out_len), 0);
            return v;
        }
        case COMPRESS_ZLIB:
            // btrfs zlib is a zlib (RFC1950) stream; the on-disk extent is padded
            // to the sector, so use the streaming decoder that stops at frame end.
            // (Compressor::Gzip auto-detects the zlib container.)
            return decompress_stream(Compressor::Gzip, src, static_cast<size_t>(out_len));
        case COMPRESS_ZSTD:
            return decompress_stream(Compressor::Zstd, src, static_cast<size_t>(out_len));
        case COMPRESS_LZO:
            return decode_btrfs_lzo(src, out_len);
        default:
            return std::nullopt;
    }
}

// Assemble a regular file's bytes from its EXTENT_DATA records.
bool build_file(Ctx& c, const Subvol& sv, uint64_t ino, uint64_t size, std::vector<uint8_t>& out) {
    if (size > MAX_FILE_BYTES) { c.truncated = true; size = MAX_FILE_BYTES; }
    if (size > c.r.size()) { c.truncated = true; size = c.r.size(); }
    out.assign(static_cast<size_t>(size), 0);
    auto it = sv.extents.find(ino);
    if (it == sv.extents.end()) return true;  // empty or metadata-only
    for (const FExt& e : it->second) {
        if (e.file_off >= size) continue;
        if (e.type == EXTENT_INLINE) {
            auto dec = decode_extent(e.compression, e.inline_data, e.ram_bytes);
            if (!dec) { c.truncated = true; continue; }
            const uint64_t n = std::min<uint64_t>(dec->size(), size - e.file_off);
            std::memcpy(out.data() + e.file_off, dec->data(), static_cast<size_t>(n));
        } else {
            if (e.disk_bytenr == 0) continue;  // sparse hole
            auto raw = read_logical(c, e.disk_bytenr, e.disk_num_bytes);
            if (!raw) { c.truncated = true; continue; }
            std::vector<uint8_t> whole;
            if (e.compression == COMPRESS_NONE) {
                whole = std::move(*raw);
            } else {
                auto dec = decode_extent(e.compression, *raw, e.ram_bytes);
                if (!dec) { c.truncated = true; continue; }
                whole = std::move(*dec);
            }
            // Take [offset, offset+num_bytes) of the decoded extent.
            if (e.offset >= whole.size()) continue;
            const uint64_t avail = std::min<uint64_t>(e.num_bytes, whole.size() - e.offset);
            const uint64_t n = std::min<uint64_t>(avail, size - e.file_off);
            std::memcpy(out.data() + e.file_off, whole.data() + e.offset, static_cast<size_t>(n));
        }
    }
    return true;
}

// Read a symlink target (stored as an inline EXTENT_DATA on the symlink inode).
std::string read_symlink(Ctx& c, const Subvol& sv, uint64_t ino, uint64_t size) {
    std::vector<uint8_t> data;
    build_file(c, sv, ino, size, data);
    return std::string(data.begin(), data.end());
}

void walk_subvol(Ctx& c, uint64_t tree_root, uint64_t subvol_id, const std::string& rel,
                 size_t depth);

// Rebuild one subvolume's directory tree from inode `ino`. `stack` guards
// directory cycles within this subvolume (inode numbers repeat across
// subvolumes, so the guard is per-subvolume).
void reconstruct_dir(Ctx& c, const Subvol& sv, std::set<uint64_t>& stack, uint64_t ino,
                     const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (!stack.insert(ino).second) return;
    auto it = sv.children.find(ino);
    if (it != sv.children.end()) {
        for (const DirEnt& e : it->second) {
            const std::string child_rel = rel.empty() ? e.name : rel + "/" + e.name;
            const std::string full = c.subdir + "/" + child_rel;
            if (e.is_subvol) {  // nested subvolume: its own tree + inode namespace
                if (c.root.make_dir(full)) c.out.dirs++;
                auto ri = c.root_items.find(e.child);
                if (ri != c.root_items.end())
                    walk_subvol(c, ri->second, e.child, child_rel, depth + 1);
                continue;
            }
            auto ino_it = sv.inodes.find(e.child);
            const uint16_t mode = ino_it != sv.inodes.end() ? ino_it->second.mode : 0;
            const uint64_t sz = ino_it != sv.inodes.end() ? ino_it->second.size : 0;
            const bool is_dir = e.ftype == FT_DIR || (mode & S_IFMT_) == S_IFDIR_;
            const bool is_lnk = e.ftype == FT_SYMLINK || (mode & S_IFMT_) == S_IFLNK_;
            if (is_dir) {
                if (c.root.make_dir(full)) c.out.dirs++;
                reconstruct_dir(c, sv, stack, e.child, child_rel, depth + 1);
            } else if (is_lnk) {
                std::string target = read_symlink(c, sv, e.child, sz);
                if (!target.empty() && target.find('\0') == std::string::npos &&
                    c.root.make_symlink(full, target))
                    c.out.symlinks++;
            } else {
                std::vector<uint8_t> data;
                build_file(c, sv, e.child, sz, data);
                if (c.root.write_file(full, data, 0644)) {
                    c.out.files++;
                    c.out.bytes += data.size();
                }
            }
        }
    }
    stack.erase(ino);
}

// Collect and rebuild one subvolume (its FS tree root at `tree_root`) under `rel`.
// The subvols_done guard stops a snapshot/subvolume from being walked twice.
void walk_subvol(Ctx& c, uint64_t tree_root, uint64_t subvol_id, const std::string& rel,
                 size_t depth) {
    if (depth > MAX_DEPTH || !c.subvols_done.insert(subvol_id).second) {
        if (depth > MAX_DEPTH) c.truncated = true;
        return;
    }
    Subvol sv;
    walk_fs_tree(c, tree_root, sv);
    std::set<uint64_t> stack;
    reconstruct_dir(c, sv, stack, FIRST_FREE_OBJECTID, rel, depth);
}

}  // namespace

bool extract_btrfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out) {
    out.offset = f.offset;
    out.type = "btrfs";
    out.root = subdir;

    const uint64_t sb = f.offset + SB_OFFSET;
    auto magic = r.bytes(sb + 64, 8);
    if (!magic || std::memcmp(magic->data(), "_BHRfS_M", 8) != 0) {
        out.status = "error:bad-superblock";
        return true;
    }
    auto root_log = u64(r, sb + 80);
    auto chunk_root = u64(r, sb + 88);
    auto sectorsize = u32(r, sb + 144);
    auto nodesize = u32(r, sb + 148);
    auto sys_size = u32(r, sb + 160);
    if (!root_log || !chunk_root || !sectorsize || !nodesize || !sys_size) {
        out.status = "error:bad-superblock";
        return true;
    }
    if (*nodesize < 512 || *nodesize > (1u << 18) || (*nodesize & (*nodesize - 1)) ||
        *sectorsize < 512 || *sectorsize > (1u << 16) || (*sectorsize & (*sectorsize - 1)) ||
        *sys_size > 2048) {
        out.status = "error:bad-superblock";
        return true;
    }
    if (!root.make_dir(subdir)) { out.status = "error:mkdir"; return true; }

    // This image's device id (dev_item.devid, @ superblock+201) — used to pick the
    // right chunk stripe on a multi-device filesystem.
    auto devid = u64(r, sb + 201);
    Ctx c{r, f.offset, *nodesize, *sectorsize, devid ? *devid : 0, root, subdir, out};

    // 1. Bootstrap chunk map from the sys_chunk_array (@811).
    auto arr = r.bytes(sb + 811, *sys_size);
    if (!arr) { out.status = "error:sys-chunk"; return true; }
    parse_sys_chunk_array(c, *arr);
    if (c.chunks.empty()) { out.status = "error:no-chunks"; return true; }

    // 2. Walk the chunk tree to add the rest of the logical->physical map.
    walk_tree(c, *chunk_root, 0, [&](uint64_t oid, uint8_t type, uint64_t koff,
                                     std::span<const uint8_t> data) {
        (void)oid;
        if (type == CHUNK_ITEM_KEY) add_chunk(c, koff, data, 0);
    });

    // 3. Walk the root tree, collecting every subvolume/FS-tree ROOT_ITEM
    //    (objectid 5 = the default subvolume, or >= 256 = user subvolumes and
    //    snapshots) as subvol_id -> tree-root logical address.
    c.walked.clear();
    walk_tree(c, *root_log, 0, [&](uint64_t oid, uint8_t type, uint64_t koff,
                                   std::span<const uint8_t> data) {
        (void)koff;
        if (type == ROOT_ITEM_KEY && (oid == FS_TREE_OBJECTID || oid >= FIRST_FREE_OBJECTID) &&
            data.size() >= 239)
            c.root_items[oid] = g64(data, 176);  // root_item.bytenr (tree root logical)
    });
    if (!c.root_items.count(FS_TREE_OBJECTID)) { out.status = "error:no-fs-tree"; return true; }

    // 4. Rebuild from the default subvolume (FS tree 5), recursing into nested
    //    subvolumes and snapshots as their mount-point directories are reached.
    walk_subvol(c, c.root_items[FS_TREE_OBJECTID], FS_TREE_OBJECTID, "", 0);

    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

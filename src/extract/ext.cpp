// ext.cpp — ext2/ext3/ext4 read-only extraction. See ext.hpp.
//
// Format reference: https://www.kernel.org/doc/html/latest/filesystems/ext4/
// Layout: superblock at base+1024; group descriptor table in the block after
// the superblock's block; each group descriptor points at an inode table; inode
// 2 is the root directory. File/dir/symlink data blocks are located either by an
// ext4 extent tree (i_flags & EXTENTS) or by the ext2/3 indirect-block pointers.
// Everything is little-endian. All disk access is range-checked through Reader,
// so hostile size/pointer fields yield holes or a partial result, never OOB.
#include "extract/ext.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint16_t EXT_MAGIC = 0xEF53;
constexpr uint16_t EXTENT_HEADER_MAGIC = 0xF30A;

// i_mode file-type bits.
constexpr uint16_t S_IFMT = 0xF000;
constexpr uint16_t S_IFREG = 0x8000;
constexpr uint16_t S_IFDIR = 0x4000;
constexpr uint16_t S_IFLNK = 0xA000;

// i_flags.
constexpr uint32_t EXT4_EXTENTS_FL = 0x80000;

// s_feature_incompat bits.
constexpr uint32_t INCOMPAT_64BIT = 0x80;

constexpr uint32_t ROOT_INO = 2;

// Guardrails against hostile / corrupt images.
constexpr size_t MAX_FILES = 2000000;
constexpr size_t MAX_DEPTH = 128;
constexpr size_t MAX_EXTENT_DEPTH = 6;
constexpr size_t MAX_EXTENTS = 1u << 20;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;  // 8 GiB per file
constexpr size_t MAX_DIR_BYTES = 64u << 20;             // a single directory's data

struct Super {
    uint64_t block_size = 0;
    uint32_t inodes_count = 0;
    uint64_t blocks_count = 0;
    uint32_t blocks_per_group = 0;
    uint32_t inodes_per_group = 0;
    uint32_t first_data_block = 0;
    uint32_t inode_size = 128;
    uint32_t desc_size = 32;
    uint32_t groups = 0;
};

struct Inode {
    uint16_t mode = 0;
    uint64_t size = 0;
    uint32_t flags = 0;
    uint64_t blocks512 = 0;    // i_blocks in 512-byte units (fast-symlink test)
    uint8_t iblock[60] = {0};  // i_block[15] area: extent root or block pointers
};

struct Ctx {
    const Reader& r;
    uint64_t base;  // absolute file offset of the ext filesystem start
    Super sb;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t files_seen = 0;
    std::set<uint32_t> stack{};  // inodes on the current recursion path (cycle guard)
};

// Absolute file offset of filesystem block `blk`.
uint64_t block_off(const Ctx& c, uint64_t blk) { return c.base + blk * c.sb.block_size; }

std::optional<uint32_t> rd32(const Reader& r, uint64_t off) {
    return r.at<uint32_t>(static_cast<size_t>(off), Endian::Little);
}
std::optional<uint16_t> rd16(const Reader& r, uint64_t off) {
    return r.at<uint16_t>(static_cast<size_t>(off), Endian::Little);
}

bool parse_super(Ctx& c) {
    const Reader& r = c.r;
    const uint64_t sbo = c.base + 1024;

    auto magic = rd16(r, sbo + 0x38);
    if (!magic || *magic != EXT_MAGIC) return false;

    auto inodes = rd32(r, sbo + 0x00);
    auto blocks_lo = rd32(r, sbo + 0x04);
    auto first_db = rd32(r, sbo + 0x14);
    auto log_bs = rd32(r, sbo + 0x18);
    auto bpg = rd32(r, sbo + 0x20);
    auto ipg = rd32(r, sbo + 0x28);
    auto rev = rd32(r, sbo + 0x4c);
    auto isize = rd16(r, sbo + 0x58);
    auto incompat = rd32(r, sbo + 0x60);
    auto dsize = rd16(r, sbo + 0xfe);
    auto blocks_hi = rd32(r, sbo + 0x150);
    if (!inodes || !blocks_lo || !first_db || !log_bs || !bpg || !ipg || !rev || !incompat)
        return false;

    if (*log_bs > 6) return false;  // block size 1KiB..64KiB
    c.sb.block_size = uint64_t(1024) << *log_bs;
    c.sb.inodes_count = *inodes;
    c.sb.blocks_count = *blocks_lo;
    const bool bit64 = (*incompat & INCOMPAT_64BIT) != 0;
    if (bit64 && blocks_hi) c.sb.blocks_count |= uint64_t(*blocks_hi) << 32;
    c.sb.first_data_block = *first_db;
    c.sb.blocks_per_group = *bpg;
    c.sb.inodes_per_group = *ipg;

    // Dynamic-rev filesystems carry the real inode/descriptor sizes.
    if (*rev >= 1) {
        c.sb.inode_size = (isize && *isize >= 128) ? *isize : 128;
        c.sb.desc_size = bit64 ? ((dsize && *dsize >= 32) ? *dsize : 64) : 32;
    } else {
        c.sb.inode_size = 128;
        c.sb.desc_size = 32;
    }

    if (c.sb.blocks_per_group == 0 || c.sb.inodes_per_group == 0) return false;
    if (c.sb.inode_size > c.sb.block_size || c.sb.inode_size == 0) return false;
    if (c.sb.blocks_count == 0) return false;
    // A dump may be shorter than the device; cap group count by what's present.
    uint64_t g = (c.sb.blocks_count - c.sb.first_data_block + c.sb.blocks_per_group - 1) /
                 c.sb.blocks_per_group;
    if (g == 0 || g > (1u << 24)) return false;
    c.sb.groups = static_cast<uint32_t>(g);
    return true;
}

// Block number of a group's inode table, from its descriptor.
std::optional<uint64_t> inode_table_block(Ctx& c, uint32_t group) {
    if (group >= c.sb.groups) return std::nullopt;
    // GDT sits in the block after the superblock's block (first_data_block + 1).
    const uint64_t gdt_block = c.sb.first_data_block + 1;
    const uint64_t desc_off = block_off(c, gdt_block) + uint64_t(group) * c.sb.desc_size;
    auto lo = rd32(c.r, desc_off + 0x08);
    if (!lo) return std::nullopt;
    uint64_t it = *lo;
    if (c.sb.desc_size >= 64) {
        auto hi = rd32(c.r, desc_off + 0x28);
        if (hi) it |= uint64_t(*hi) << 32;
    }
    return it;
}

bool read_inode(Ctx& c, uint32_t ino, Inode& out) {
    if (ino == 0 || ino > c.sb.inodes_count) return false;
    const uint32_t group = (ino - 1) / c.sb.inodes_per_group;
    const uint32_t index = (ino - 1) % c.sb.inodes_per_group;
    auto it = inode_table_block(c, group);
    if (!it) return false;
    const uint64_t ioff = block_off(c, *it) + uint64_t(index) * c.sb.inode_size;

    auto mode = rd16(c.r, ioff + 0x00);
    auto size_lo = rd32(c.r, ioff + 0x04);
    auto blocks_lo = rd32(c.r, ioff + 0x1c);
    auto flags = rd32(c.r, ioff + 0x20);
    auto size_hi = rd32(c.r, ioff + 0x6c);
    auto ib = c.r.bytes(static_cast<size_t>(ioff + 0x28), 60);
    if (!mode || !size_lo || !flags || !ib) return false;

    out.mode = *mode;
    out.flags = *flags;
    out.blocks512 = blocks_lo ? *blocks_lo : 0;
    out.size = *size_lo;
    if ((*mode & S_IFMT) == S_IFREG && size_hi) out.size |= uint64_t(*size_hi) << 32;
    std::memcpy(out.iblock, ib->data(), 60);
    return true;
}

// One resolved run of contiguous blocks: logical .. logical+len-1 map to
// physical .. physical+len-1. physical 0 marks a hole (read as zeros).
struct Extent {
    uint32_t logical;
    uint32_t len;
    uint64_t physical;
};

// Parse an extent tree node (12-byte header + entries) at absolute offset `at`,
// appending leaf extents to `out`. `avail` bounds the node; recurses through
// index nodes to `MAX_EXTENT_DEPTH`.
void collect_extents(Ctx& c, uint64_t at, uint64_t avail, size_t depth,
                     std::vector<Extent>& out) {
    if (depth > MAX_EXTENT_DEPTH || out.size() > MAX_EXTENTS) { c.truncated = true; return; }
    if (avail < 12) return;
    auto emagic = rd16(c.r, at + 0x00);
    auto entries = rd16(c.r, at + 0x02);
    auto node_depth = rd16(c.r, at + 0x06);
    if (!emagic || *emagic != EXTENT_HEADER_MAGIC || !entries || !node_depth) return;

    const uint64_t max_by_space = (avail - 12) / 12;
    uint64_t n = *entries;
    if (n > max_by_space) { n = max_by_space; c.truncated = true; }

    for (uint64_t i = 0; i < n; ++i) {
        const uint64_t e = at + 12 + i * 12;
        if (*node_depth == 0) {
            auto ee_block = rd32(c.r, e + 0x00);
            auto ee_len = rd16(c.r, e + 0x04);
            auto start_hi = rd16(c.r, e + 0x06);
            auto start_lo = rd32(c.r, e + 0x08);
            if (!ee_block || !ee_len || !start_hi || !start_lo) { c.truncated = true; return; }
            uint32_t len = *ee_len;
            if (len > 32768) len -= 32768;  // uninitialized extent: still allocated
            if (len == 0) continue;
            if (out.size() + 1 > MAX_EXTENTS) { c.truncated = true; return; }
            out.push_back({*ee_block, len, (uint64_t(*start_hi) << 32) | *start_lo});
        } else {
            auto ei_block = rd32(c.r, e + 0x00);
            auto leaf_lo = rd32(c.r, e + 0x04);
            auto leaf_hi = rd16(c.r, e + 0x08);
            (void)ei_block;
            if (!leaf_lo || !leaf_hi) { c.truncated = true; return; }
            uint64_t child = (uint64_t(*leaf_hi) << 32) | *leaf_lo;
            collect_extents(c, block_off(c, child), c.sb.block_size, depth + 1, out);
        }
    }
}

// Resolve logical block L to a physical block via the ext2/3 indirect scheme.
// Returns 0 for a hole or an out-of-range pointer.
uint64_t indirect_resolve(Ctx& c, const Inode& in, uint64_t L) {
    const uint64_t ppb = c.sb.block_size / 4;  // pointers per block
    auto ptr_at = [&](uint64_t blk, uint64_t idx) -> uint64_t {
        if (blk == 0) return 0;
        auto v = rd32(c.r, block_off(c, blk) + idx * 4);
        return v ? *v : 0;
    };
    auto iblk = [&](unsigned i) -> uint64_t {
        uint32_t v;
        std::memcpy(&v, in.iblock + i * 4, 4);  // little-endian on disk == native LE reads
        return v;
    };
    if (L < 12) return iblk(static_cast<unsigned>(L));
    L -= 12;
    if (L < ppb) return ptr_at(iblk(12), L);
    L -= ppb;
    if (L < ppb * ppb) return ptr_at(ptr_at(iblk(13), L / ppb), L % ppb);
    L -= ppb * ppb;
    if (L < ppb * ppb * ppb) {
        uint64_t a = ptr_at(iblk(14), L / (ppb * ppb));
        uint64_t b = ptr_at(a, (L / ppb) % ppb);
        return ptr_at(b, L % ppb);
    }
    return 0;
}

// Read a file/dir/slow-symlink's content into `out` (up to `cap` bytes).
void read_content(Ctx& c, const Inode& in, uint64_t cap, std::vector<uint8_t>& out) {
    uint64_t size = in.size;
    if (size > cap) { size = cap; c.truncated = true; }
    if (size == 0) return;
    const uint64_t bs = c.sb.block_size;
    const uint64_t nblocks = (size + bs - 1) / bs;
    out.reserve(static_cast<size_t>(size));

    std::vector<Extent> extents;
    const bool use_extents = (in.flags & EXT4_EXTENTS_FL) != 0;

    // The extent tree root lives in the 60-byte i_block area (inside the inode,
    // not at a fixed file offset), so parse it from the copied bytes; index
    // nodes below the root are read from their own disk blocks via collect_extents.
    if (use_extents) {
        auto rd16b = [&](unsigned o) { uint16_t v; std::memcpy(&v, in.iblock + o, 2); return v; };
        auto rd32b = [&](unsigned o) { uint32_t v; std::memcpy(&v, in.iblock + o, 4); return v; };
        if (rd16b(0) == EXTENT_HEADER_MAGIC) {
            uint16_t entries = rd16b(2);
            uint16_t node_depth = rd16b(6);
            const unsigned max_root = (60 - 12) / 12;  // 4 entries fit in i_block
            if (entries > max_root) { entries = max_root; c.truncated = true; }
            for (unsigned i = 0; i < entries; ++i) {
                const unsigned e = 12 + i * 12;
                if (node_depth == 0) {
                    uint32_t ee_block = rd32b(e + 0);
                    uint16_t ee_len = rd16b(e + 4);
                    uint16_t start_hi = rd16b(e + 6);
                    uint32_t start_lo = rd32b(e + 8);
                    uint32_t len = ee_len > 32768 ? ee_len - 32768 : ee_len;
                    if (len == 0) continue;
                    extents.push_back({ee_block, len, (uint64_t(start_hi) << 32) | start_lo});
                } else {
                    uint32_t leaf_lo = rd32b(e + 4);
                    uint16_t leaf_hi = rd16b(e + 8);
                    uint64_t child = (uint64_t(leaf_hi) << 32) | leaf_lo;
                    collect_extents(c, block_off(c, child), c.sb.block_size, 1, extents);
                }
            }
        }
    }

    for (uint64_t L = 0; L < nblocks; ++L) {
        uint64_t phys = 0;
        if (use_extents) {
            for (const auto& ex : extents) {
                if (L >= ex.logical && L < uint64_t(ex.logical) + ex.len) {
                    phys = ex.physical + (L - ex.logical);
                    break;
                }
            }
        } else {
            phys = indirect_resolve(c, in, L);
        }
        const uint64_t want = std::min<uint64_t>(bs, size - L * bs);
        if (phys == 0 || phys >= c.sb.blocks_count) {
            out.insert(out.end(), static_cast<size_t>(want), 0);  // hole / bad ptr
            if (phys >= c.sb.blocks_count && phys != 0) c.truncated = true;
            continue;
        }
        auto span = c.r.bytes(static_cast<size_t>(block_off(c, phys)), static_cast<size_t>(want));
        if (!span) {
            out.insert(out.end(), static_cast<size_t>(want), 0);  // block beyond a truncated dump
            c.truncated = true;
            continue;
        }
        out.insert(out.end(), span->begin(), span->end());
    }
}

void walk_dir(Ctx& c, uint32_t ino, const std::string& rel, size_t depth);

// Handle one directory entry: create the child under `rel`.
void handle_entry(Ctx& c, uint32_t child_ino, const std::string& name, const std::string& rel,
                  size_t depth) {
    if (name.empty() || name == "." || name == "..") return;
    if (name.find('/') != std::string::npos || name.find('\0') != std::string::npos) return;
    Inode in;
    if (!read_inode(c, child_ino, in)) { c.truncated = true; return; }
    const std::string child_rel = rel.empty() ? name : rel + "/" + name;
    const std::string full = c.subdir + "/" + child_rel;
    const uint16_t type = in.mode & S_IFMT;

    if (type == S_IFDIR) {
        if (c.root.make_dir(full)) c.out.dirs++;
        walk_dir(c, child_ino, child_rel, depth + 1);
    } else if (type == S_IFLNK) {
        std::string target;
        if (in.blocks512 == 0 && in.size <= 60) {
            target.assign(reinterpret_cast<const char*>(in.iblock),
                          static_cast<size_t>(in.size));  // fast symlink (inline)
        } else {
            std::vector<uint8_t> buf;
            read_content(c, in, 4096, buf);
            target.assign(buf.begin(), buf.end());
        }
        if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
        if (!target.empty() && c.root.make_symlink(full, target)) c.out.symlinks++;
    } else if (type == S_IFREG) {
        std::vector<uint8_t> data;
        read_content(c, in, MAX_FILE_BYTES, data);
        if (c.root.write_file(full, data, in.mode & 0777)) {
            c.out.files++;
            c.out.bytes += data.size();
        } else {
            c.out.warnings.push_back("write failed: " + child_rel);
        }
    }
    // Other types (fifo/chr/blk/sock): skipped.
}

void walk_dir(Ctx& c, uint32_t ino, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (c.files_seen++ > MAX_FILES) { c.truncated = true; return; }
    if (c.stack.count(ino)) return;  // directory cycle (corrupt image)
    c.stack.insert(ino);

    Inode dir;
    if (read_inode(c, ino, dir) && (dir.mode & S_IFMT) == S_IFDIR) {
        std::vector<uint8_t> content;
        read_content(c, dir, MAX_DIR_BYTES, content);
        size_t pos = 0;
        while (pos + 8 <= content.size()) {
            uint32_t e_ino;
            uint16_t rec_len;
            std::memcpy(&e_ino, content.data() + pos, 4);
            std::memcpy(&rec_len, content.data() + pos + 4, 2);
            const uint8_t name_len = content[pos + 6];
            if (rec_len < 8) break;  // malformed; stop this directory
            if (e_ino != 0 && name_len > 0 && pos + 8 + name_len <= content.size()) {
                std::string name(reinterpret_cast<const char*>(content.data() + pos + 8), name_len);
                handle_entry(c, e_ino, name, rel, depth);
            }
            pos += rec_len;
        }
    }
    c.stack.erase(ino);
}

}  // namespace

bool extract_ext(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.offset = f.offset;
    out.type = "ext";
    out.root = subdir;

    Ctx c{r, f.offset, {}, root, subdir, out};
    if (!parse_super(c)) {
        out.status = "error:bad-superblock";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    walk_dir(c, ROOT_INO, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

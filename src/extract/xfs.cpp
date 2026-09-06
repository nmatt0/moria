// xfs.cpp — XFS extraction. See xfs.hpp. All fields big-endian.
//
//  - Superblock @0: magic 'XFSB', blocksize @4, rootino @56, agblocks @84,
//    agcount @88, inodesize @104, inopblock @106, versionnum @100, and the shift
//    logs blocklog @120, inopblog @123, agblklog @124, dirblklog @192.
//  - Inode number -> location: offset = ino & (inopblock-1); agbno = (ino >>
//    inopblog) & (2^agblklog - 1); agno = ino >> (inopblog+agblklog); byte =
//    (agno*agblocks + agbno)*blocksize + offset*inodesize.
//  - Inode core (xfs_dinode): magic 'IN' @0, mode @2, version @4, format @5,
//    size @56, nextents @76, forkoff @82. The data fork (literal area) starts at
//    100 (v1/v2) or 176 (v3/v5); it is local (inline), extents (packed 16-byte
//    bmbt_rec array), or a bmbt B-tree (format 3).
//  - Directory: shortform (inline in a local-format dir inode) or data blocks
//    (xfs_dir2_data / _block) reached through the data-fork extents.
#include "extract/xfs.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint32_t XFS_SB_MAGIC = 0x58465342;    // 'XFSB'
constexpr uint16_t XFS_DINODE_MAGIC = 0x494E;    // 'IN'

// Directory data-block magics (v4 / v5).
constexpr uint32_t DIR2_DATA = 0x58443244;  // 'XD2D'
constexpr uint32_t DIR3_DATA = 0x58444433;  // 'XDD3'
constexpr uint32_t DIR2_BLOCK = 0x58443242; // 'XD2B'
constexpr uint32_t DIR3_BLOCK = 0x58444233; // 'XDB3'

constexpr uint8_t FMT_LOCAL = 1;
constexpr uint8_t FMT_EXTENTS = 2;
constexpr uint8_t FMT_BTREE = 3;

constexpr uint16_t S_IFMT_ = 0170000;
constexpr uint16_t S_IFDIR_ = 0040000;
constexpr uint16_t S_IFREG_ = 0100000;
constexpr uint16_t S_IFLNK_ = 0120000;

constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;
constexpr size_t MAX_INODES = 4000000;
constexpr size_t MAX_DEPTH = 128;
constexpr size_t MAX_EXTENTS = 2000000;

std::optional<uint16_t> u16(const Reader& r, uint64_t o) { return r.at<uint16_t>(o, Endian::Big); }
std::optional<uint32_t> u32(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Big); }
std::optional<uint64_t> u64(const Reader& r, uint64_t o) { return r.at<uint64_t>(o, Endian::Big); }

struct Sb {
    uint64_t base = 0;
    uint32_t blocksize = 4096;
    uint16_t inodesize = 512;
    uint32_t agblocks = 0;
    uint32_t agcount = 0;
    uint64_t rootino = 0;
    uint8_t inopblog = 0;
    uint8_t agblklog = 0;
    uint8_t dirblklog = 0;
    bool v5 = false;
    bool nrext64 = false;  // NREXT64 feature: data-fork extent count is a u64 @24
    bool has_ftype = false;  // directory entries carry a file-type byte
    uint32_t dirblocksize = 4096;
};

struct Ext {
    uint64_t startoff = 0;
    uint64_t startblock = 0;
    uint64_t count = 0;
};

struct Ctx {
    const Reader& r;
    Sb sb;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t inodes = 0;
    std::set<uint64_t> stack{};
};

// Absolute byte offset of an fs-block number (agno:agbno packed).
uint64_t fsb_off(const Sb& sb, uint64_t fsb) {
    const uint64_t agno = fsb >> sb.agblklog;
    const uint64_t agbno = fsb & ((uint64_t(1) << sb.agblklog) - 1);
    return sb.base + (agno * sb.agblocks + agbno) * sb.blocksize;
}

// Absolute byte offset of an inode number.
uint64_t ino_off(const Sb& sb, uint64_t ino) {
    const uint64_t off = ino & ((uint64_t(1) << sb.inopblog) - 1);
    const uint64_t agbno = (ino >> sb.inopblog) & ((uint64_t(1) << sb.agblklog) - 1);
    const uint64_t agno = ino >> (sb.inopblog + sb.agblklog);
    return sb.base + (agno * sb.agblocks + agbno) * sb.blocksize + off * sb.inodesize;
}

struct Inode {
    uint16_t mode = 0;
    uint8_t format = 0;
    uint64_t size = 0;
    uint64_t nextents = 0;
    uint8_t forkoff = 0;      // in 8-byte units; 0 = no attr fork
    uint64_t data_off = 0;    // absolute offset of the data fork (literal area)
    uint64_t data_bytes = 0;  // size of the data fork within the literal area
};

std::optional<Inode> read_inode(Ctx& c, uint64_t ino) {
    const uint64_t io = ino_off(c.sb, ino);
    auto magic = u16(c.r, io);
    if (!magic || *magic != XFS_DINODE_MAGIC) return std::nullopt;
    auto mode = u16(c.r, io + 2);
    auto ver = c.r.bytes(io + 4, 1);
    auto fmt = c.r.bytes(io + 5, 1);
    auto size = u64(c.r, io + 56);
    auto fko = c.r.bytes(io + 82, 1);
    if (!mode || !ver || !fmt || !size || !fko) return std::nullopt;
    // Data-fork extent count: a u64 di_big_nextents @24 with the NREXT64 feature,
    // else the classic u32 di_nextents @76.
    uint64_t nextents;
    if (c.sb.nrext64) {
        auto v = u64(c.r, io + 24);
        if (!v) return std::nullopt;
        nextents = *v;
    } else {
        auto v = u32(c.r, io + 76);
        if (!v) return std::nullopt;
        nextents = *v;
    }
    Inode n;
    n.mode = *mode;
    n.format = (*fmt)[0];
    n.size = *size;
    n.nextents = nextents;
    n.forkoff = (*fko)[0];
    const uint64_t literal = ((*ver)[0] >= 3) ? 176 : 100;
    n.data_off = io + literal;
    n.data_bytes = n.forkoff ? uint64_t(n.forkoff) * 8 : (c.sb.inodesize - literal);
    return n;
}

Ext decode_bmbt(uint64_t l0, uint64_t l1) {
    Ext e;
    e.startoff = (l0 >> 9) & ((uint64_t(1) << 54) - 1);
    e.startblock = ((l0 & 0x1FF) << 43) | (l1 >> 21);
    e.count = l1 & ((uint64_t(1) << 21) - 1);
    return e;
}

// Long-form bmbt block header size (v5 has crc/uuid/owner).
uint64_t bmbt_hdr_size(const Sb& sb) { return sb.v5 ? 72 : 24; }

void collect_bmbt_block(Ctx& c, uint64_t fsb, std::vector<Ext>& out, std::set<uint64_t>& seen,
                        size_t depth);

// Walk a bmbt node's pointer array (interior node): keys then ptrs.
void bmbt_walk_ptrs(Ctx& c, uint64_t pos, uint32_t numrecs, uint64_t maxrecs,
                    std::vector<Ext>& out, std::set<uint64_t>& seen, size_t depth) {
    const uint64_t ptr_base = pos + maxrecs * 8;  // keys[maxrecs] then ptrs
    for (uint32_t i = 0; i < numrecs; ++i) {
        auto p = u64(c.r, ptr_base + uint64_t(i) * 8);
        if (!p || *p == 0) { c.truncated = true; break; }
        collect_bmbt_block(c, *p, out, seen, depth + 1);
        if (out.size() > MAX_EXTENTS) { c.truncated = true; break; }
    }
}

void collect_bmbt_block(Ctx& c, uint64_t fsb, std::vector<Ext>& out, std::set<uint64_t>& seen,
                        size_t depth) {
    if (depth > 32 || !seen.insert(fsb).second) { c.truncated = true; return; }
    const uint64_t bo = fsb_off(c.sb, fsb);
    auto level = u16(c.r, bo + 4);
    auto numrecs = u16(c.r, bo + 6);
    if (!level || !numrecs) { c.truncated = true; return; }
    const uint64_t hdr = bmbt_hdr_size(c.sb);
    if (*level == 0) {  // leaf: 16-byte bmbt_rec array
        for (uint32_t i = 0; i < *numrecs; ++i) {
            auto l0 = u64(c.r, bo + hdr + uint64_t(i) * 16);
            auto l1 = u64(c.r, bo + hdr + uint64_t(i) * 16 + 8);
            if (!l0 || !l1) { c.truncated = true; break; }
            out.push_back(decode_bmbt(*l0, *l1));
            if (out.size() > MAX_EXTENTS) { c.truncated = true; break; }
        }
    } else {  // interior node
        const uint64_t maxrecs = (c.sb.blocksize - hdr) / 16;
        bmbt_walk_ptrs(c, bo + hdr, *numrecs, maxrecs, out, seen, depth);
    }
}

// Collect all data-fork extents of an inode (extents or btree format).
void collect_extents(Ctx& c, const Inode& n, std::vector<Ext>& out) {
    if (n.format == FMT_EXTENTS) {
        const uint64_t maxe = n.data_bytes / 16;
        const uint64_t cnt = std::min<uint64_t>(n.nextents, maxe);
        for (uint64_t i = 0; i < cnt; ++i) {
            auto l0 = u64(c.r, n.data_off + i * 16);
            auto l1 = u64(c.r, n.data_off + i * 16 + 8);
            if (!l0 || !l1) { c.truncated = true; break; }
            out.push_back(decode_bmbt(*l0, *l1));
        }
        if (n.nextents > maxe) c.truncated = true;
    } else if (n.format == FMT_BTREE) {
        // Inode bmbt root (xfs_bmdr_block): level @0, numrecs @2, keys @4, ptrs
        // after maxrecs keys where maxrecs = (fork_bytes - 4) / 16.
        auto numrecs = u16(c.r, n.data_off + 2);
        if (!numrecs) { c.truncated = true; return; }
        const uint64_t maxrecs = (n.data_bytes >= 4) ? (n.data_bytes - 4) / 16 : 0;
        std::set<uint64_t> seen;
        bmbt_walk_ptrs(c, n.data_off + 4, *numrecs, maxrecs, out, seen, 0);
    }
}

// Read `size` bytes of file data assembled from `exts` (holes -> zeros).
bool read_file_data(Ctx& c, const std::vector<Ext>& exts, uint64_t size,
                    std::vector<uint8_t>& out) {
    out.clear();
    if (size > MAX_FILE_BYTES) { c.truncated = true; size = MAX_FILE_BYTES; }
    // A file cannot be larger than the image; clamp so a corrupt di_size cannot
    // request a huge zero-fill allocation.
    if (size > c.r.size()) { c.truncated = true; size = c.r.size(); }
    out.assign(static_cast<size_t>(size), 0);  // sparse default
    const uint64_t bs = c.sb.blocksize;
    for (const Ext& e : exts) {
        const uint64_t file_off = e.startoff * bs;
        if (file_off >= size) continue;
        const uint64_t avail = std::min<uint64_t>(e.count * bs, size - file_off);
        auto d = c.r.bytes(static_cast<size_t>(fsb_off(c.sb, e.startblock)),
                           static_cast<size_t>(avail));
        if (!d) { c.truncated = true; continue; }
        std::memcpy(out.data() + file_off, d->data(), d->size());
    }
    return true;
}

void walk(Ctx& c, uint64_t ino, const std::string& rel, size_t depth);

// Parse a shortform directory (inline in a local-format dir inode).
void walk_shortform_dir(Ctx& c, const Inode& n, const std::string& rel, size_t depth) {
    const uint64_t p0 = n.data_off;
    auto cnt = c.r.bytes(p0, 2);
    if (!cnt) return;
    const uint8_t count = (*cnt)[0];
    const uint8_t i8 = (*cnt)[1];
    uint64_t p = p0 + 2 + (i8 ? 8 : 4);  // header: count,i8count,parent
    for (uint8_t k = 0; k < count; ++k) {
        auto nl = c.r.bytes(p, 1);
        if (!nl) { c.truncated = true; break; }
        const uint8_t namelen = (*nl)[0];
        // entry: namelen(1), offset(2), name[namelen], ftype(1, v5), inumber(4/8)
        const uint64_t name_off = p + 3;
        auto nm = c.r.bytes(name_off, namelen);
        if (!nm) { c.truncated = true; break; }
        const uint64_t ftype_off = name_off + namelen;
        const uint64_t ino_field = ftype_off + (c.sb.has_ftype ? 1 : 0);
        uint64_t child;
        if (i8) {
            auto v = u64(c.r, ino_field);
            if (!v) { c.truncated = true; break; }
            child = *v;
        } else {
            auto v = u32(c.r, ino_field);
            if (!v) { c.truncated = true; break; }
            child = *v;
        }
        std::string name(reinterpret_cast<const char*>(nm->data()), namelen);
        p = ino_field + (i8 ? 8 : 4);
        if (name.empty() || name == "." || name == ".." ||
            name.find('/') != std::string::npos || name.find('\0') != std::string::npos)
            continue;
        walk(c, child, rel.empty() ? name : rel + "/" + name, depth + 1);
    }
}

// Parse one directory data block (xfs_dir2_data / _block) for name->inode entries.
// `data_end` bounds the entry area (a block-format dir has a leaf tail at the end).
void parse_dir_data_block(Ctx& c, std::span<const uint8_t> blk, uint64_t entries_start,
                          uint64_t data_end, const std::string& rel, size_t depth) {
    uint64_t p = entries_start;
    while (p + 8 <= data_end && p + 8 <= blk.size()) {
        const uint16_t tag = (uint16_t(blk[p]) << 8) | blk[p + 1];
        if (tag == 0xFFFF) {  // xfs_dir2_data_unused: freetag, length, ...
            const uint16_t len = (uint16_t(blk[p + 2]) << 8) | blk[p + 3];
            if (len < 8) break;
            p += len;
            continue;
        }
        // xfs_dir2_data_entry: inumber(8), namelen(1), name[], ftype(1 v5), tag(2)
        if (p + 9 > blk.size()) break;
        uint64_t child = 0;
        for (int i = 0; i < 8; ++i) child = (child << 8) | blk[p + i];
        const uint8_t namelen = blk[p + 8];
        if (namelen == 0 || p + 9 + namelen > blk.size()) break;
        std::string name(reinterpret_cast<const char*>(&blk[p + 9]), namelen);
        uint64_t entlen = 8 + 1 + namelen + (c.sb.has_ftype ? 1 : 0) + 2;  // + tag
        entlen = (entlen + 7) & ~uint64_t(7);                       // 8-byte aligned
        p += entlen;
        if (name == "." || name == ".." || name.find('/') != std::string::npos ||
            name.find('\0') != std::string::npos)
            continue;
        walk(c, child, rel.empty() ? name : rel + "/" + name, depth + 1);
    }
}

// Walk a directory stored in data blocks (format extents/btree): read the data
// fork's extents and parse every directory data block they map.
void walk_block_dir(Ctx& c, const Inode& n, const std::string& rel, size_t depth) {
    std::vector<Ext> exts;
    collect_extents(c, n, exts);
    const uint64_t dbs = c.sb.dirblocksize;
    const uint64_t bs = c.sb.blocksize;
    const uint64_t blocks_per_dirblk = dbs / bs ? dbs / bs : 1;
    // Directory logical offset of the leaf area; data blocks sit below it.
    const uint64_t leaf_doff = uint64_t(32) * 1024 * 1024 * 1024 / dbs;  // XFS_DIR2_LEAF_OFFSET
    for (const Ext& e : exts) {
        for (uint64_t b = 0; b < e.count; b += blocks_per_dirblk) {
            const uint64_t dblk = (e.startoff + b) / blocks_per_dirblk;
            if (dblk >= leaf_doff) continue;  // leaf/free block, not directory data
            const uint64_t off = fsb_off(c.sb, e.startblock + b);
            auto d = c.r.bytes(static_cast<size_t>(off), static_cast<size_t>(dbs));
            if (!d) { c.truncated = true; continue; }
            uint32_t magic = (uint32_t((*d)[0]) << 24) | (uint32_t((*d)[1]) << 16) |
                             (uint32_t((*d)[2]) << 8) | (*d)[3];
            uint64_t entries_start, data_end = d->size();
            if (magic == DIR3_DATA || magic == DIR3_BLOCK) {
                entries_start = 64;  // xfs_dir3_data_hdr
            } else if (magic == DIR2_DATA || magic == DIR2_BLOCK) {
                entries_start = 16;  // xfs_dir2_data_hdr
            } else {
                continue;  // not a data block (leaf/free/node)
            }
            if (magic == DIR3_BLOCK || magic == DIR2_BLOCK) {
                // single-block dir: a xfs_dir2_block_tail {count,stale} at the end,
                // preceded by count leaf entries (8 bytes each).
                if (d->size() >= 8) {
                    uint32_t cnt = (uint32_t((*d)[d->size() - 8]) << 24) |
                                   (uint32_t((*d)[d->size() - 7]) << 16) |
                                   (uint32_t((*d)[d->size() - 6]) << 8) | (*d)[d->size() - 5];
                    uint64_t tail = 8 + uint64_t(cnt) * 8;
                    data_end = d->size() > tail ? d->size() - tail : 0;
                }
            }
            parse_dir_data_block(c, *d, entries_start, data_end, rel, depth);
        }
    }
}

void walk(Ctx& c, uint64_t ino, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH || ++c.inodes > MAX_INODES) { c.truncated = true; return; }
    if (!c.stack.insert(ino).second) return;  // cycle guard
    auto no = read_inode(c, ino);
    if (!no) { c.truncated = true; c.stack.erase(ino); return; }
    const Inode& n = *no;
    const uint16_t type = n.mode & S_IFMT_;
    const std::string full = c.subdir + (rel.empty() ? "" : "/" + rel);

    if (type == S_IFDIR_) {
        if (!rel.empty()) c.root.make_dir(full), c.out.dirs++;
        if (n.format == FMT_LOCAL) walk_shortform_dir(c, n, rel, depth);
        else walk_block_dir(c, n, rel, depth);
    } else if (type == S_IFLNK_) {
        std::string target;
        if (n.format == FMT_LOCAL) {
            auto d = c.r.bytes(n.data_off, static_cast<size_t>(std::min<uint64_t>(n.size, 4096)));
            if (d) target.assign(d->begin(), d->end());
        } else {
            std::vector<Ext> exts;
            collect_extents(c, n, exts);
            std::vector<uint8_t> data;
            read_file_data(c, exts, n.size, data);
            target.assign(data.begin(), data.end());
        }
        if (!target.empty() && target.find('\0') == std::string::npos &&
            c.root.make_symlink(full, target))
            c.out.symlinks++;
    } else if (type == S_IFREG_) {
        std::vector<uint8_t> data;
        if (n.format == FMT_LOCAL) {
            auto d = c.r.bytes(n.data_off, static_cast<size_t>(std::min<uint64_t>(n.size, n.data_bytes)));
            if (d) data.assign(d->begin(), d->end());
            else c.truncated = true;
        } else {
            std::vector<Ext> exts;
            collect_extents(c, n, exts);
            read_file_data(c, exts, n.size, data);
        }
        if (c.root.write_file(full, data, 0644)) {
            c.out.files++;
            c.out.bytes += data.size();
        }
    }
    c.stack.erase(ino);
}

}  // namespace

bool extract_xfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.offset = f.offset;
    out.type = "xfs";
    out.root = subdir;

    const uint64_t sbo = f.offset;
    auto magic = u32(r, sbo);
    if (!magic || *magic != XFS_SB_MAGIC) { out.status = "error:bad-superblock"; return true; }
    auto bs = u32(r, sbo + 4);
    auto rootino = u64(r, sbo + 56);
    auto agblocks = u32(r, sbo + 84);
    auto agcount = u32(r, sbo + 88);
    auto vernum = u16(r, sbo + 100);
    auto inodesize = u16(r, sbo + 104);
    auto inopblog = r.bytes(sbo + 123, 1);
    auto agblklog = r.bytes(sbo + 124, 1);
    auto dirblklog = r.bytes(sbo + 192, 1);
    auto feat_incompat = u32(r, sbo + 216);  // v5; 0 if absent
    if (!bs || !rootino || !agblocks || !agcount || !inodesize || !inopblog || !agblklog ||
        !dirblklog || !vernum) {
        out.status = "error:bad-superblock";
        return true;
    }
    Sb sb;
    sb.base = f.offset;
    sb.blocksize = *bs;
    sb.inodesize = *inodesize;
    sb.agblocks = *agblocks;
    sb.agcount = *agcount;
    sb.rootino = *rootino;
    sb.inopblog = (*inopblog)[0];
    sb.agblklog = (*agblklog)[0];
    sb.dirblklog = (*dirblklog)[0];
    sb.v5 = (*vernum & 0x0F) == 5;
    sb.nrext64 = sb.v5 && feat_incompat && (*feat_incompat & 0x20);  // NREXT64
    // Directory entries carry a file-type byte when the FTYPE feature is set:
    // v5 => features_incompat bit 0x1; v4 => features2 (@200) bit 0x200.
    if (sb.v5) {
        sb.has_ftype = feat_incompat && (*feat_incompat & 0x1);
    } else {
        auto feat2 = u32(r, sbo + 200);
        sb.has_ftype = feat2 && (*feat2 & 0x200);
    }
    if (sb.blocksize < 512 || sb.blocksize > (1u << 16) || (sb.blocksize & (sb.blocksize - 1)) ||
        sb.inodesize < 256 || sb.inodesize > sb.blocksize || sb.agblklog > 32 || sb.inopblog > 8 ||
        sb.agblocks == 0 || sb.dirblklog > 8) {
        out.status = "error:bad-superblock";
        return true;
    }
    sb.dirblocksize = sb.blocksize << sb.dirblklog;  // dirblklog <= 8, no overflow

    if (!root.make_dir(subdir)) { out.status = "error:mkdir"; return true; }
    Ctx c{r, sb, root, subdir, out};
    walk(c, sb.rootino, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

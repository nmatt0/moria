// f2fs.cpp — F2FS extraction. See f2fs.hpp.
//
// Layout (all little-endian, block size from the superblock, usually 4096):
//  - Superblock @ base+1024: magic 0xF2F52010, log_blocksize, log_blocks_per_seg,
//    and the start block of each area (cp/sit/nat/ssa/main) plus root_ino.
//  - Checkpoint: two packs (at cp_blkaddr and cp_blkaddr + blocks_per_seg); the
//    one with the greater version whose header/footer versions agree is current.
//    It carries the NAT version bitmap (which of two NAT copies is live per NAT
//    block) and, in the hot-data summary block, a NAT journal of recent updates.
//  - NAT: maps a node id (nid) to the physical block of its node. Entry = {u8
//    version, le32 ino, le32 block_addr}, 455 per block; nid's entry is in NAT
//    block nid/455, copy chosen by the bitmap, overridden by the journal.
//  - Node block: an inode (i_mode/i_size/i_inline, direct data pointers i_addr[],
//    and 5 node ids i_nid[] for direct/indirect/double-indirect trees) or a
//    direct/indirect node (array of block addrs / nids). Footer @ block end.
//  - Directory: dentry blocks {bitmap, reserved, dir_entry[], filename[][8]} in
//    the dir's data blocks, or inline in the inode. Files may store data inline.
// Walk starts at the root inode (nid 3). All reads go through the Reader.
#include "extract/f2fs.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <span>
#include <map>
#include <string>
#include <vector>

#include "extract/safepath.hpp"
#include "extract/decompress.hpp"

namespace ft {

namespace {

constexpr uint32_t F2FS_MAGIC = 0xF2F52010;
constexpr size_t SB_OFFSET = 1024;

// Per-file compression (i_flags & F2FS_COMPR_FL). A compressed file's data blocks
// are grouped into clusters of 2^i_log_cluster_size logical blocks; a cluster whose
// first block address is the COMPRESS_ADDR sentinel is stored compressed (a
// `compress_data` header {le32 clen; le32 chksum; le32 reserved[4]} then clen bytes
// of codec output, spread across the cluster's remaining real block addresses),
// decompressing to exactly one full cluster. Partial tail clusters are stored raw.
constexpr uint32_t F2FS_COMPR_FL = 0x00000004;
constexpr uint32_t COMPRESS_ADDR = 0xFFFFFFFEu;
constexpr uint32_t COMPRESS_HEADER_SIZE = 24;  // sizeof(struct compress_data)
constexpr uint8_t COMPR_LZO = 0, COMPR_LZ4 = 1, COMPR_ZSTD = 2, COMPR_LZORLE = 3;

// i_inline flags.
constexpr uint8_t INLINE_XATTR = 0x01;
constexpr uint8_t INLINE_DATA = 0x02;
constexpr uint8_t INLINE_DENTRY = 0x04;
constexpr uint8_t EXTRA_ATTR = 0x20;

// superblock feature bits we care about.
constexpr uint32_t FEATURE_FLEXIBLE_INLINE_XATTR = 0x0040;

constexpr uint32_t DEFAULT_INLINE_XATTR_ADDRS = 50;
constexpr uint32_t NAT_ENTRY_SIZE = 9;

// dentry file types.
constexpr uint8_t FT_DIR = 2;
constexpr uint8_t FT_SYMLINK = 7;

constexpr uint32_t NULL_ADDR = 0;
constexpr uint32_t NEW_ADDR = 0xFFFFFFFFu;

constexpr uint16_t S_IFMT = 0170000;
constexpr uint16_t S_IFDIR = 0040000;
constexpr uint16_t S_IFREG = 0100000;
constexpr uint16_t S_IFLNK = 0120000;

constexpr size_t MAX_DEPTH = 128;
constexpr size_t MAX_INODES = 4000000;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;

struct Sb {
    uint64_t base = 0;         // absolute offset of the f2fs image
    uint32_t bs = 4096;        // block size
    uint32_t log_bs = 12;
    uint32_t log_blocks_per_seg = 9;
    uint32_t nat_blkaddr = 0;
    uint32_t root_ino = 3;
    uint32_t feature = 0;
    uint64_t nat_half_blocks = 0;          // blocks in one NAT copy
    uint32_t nat_entry_per_block = 455;
    std::vector<uint8_t> nat_bitmap;       // per NAT block: 1 => second copy
    std::map<uint32_t, uint32_t> nat_journal;  // nid -> block_addr (tiny; ordered)

    // derived inode geometry
    uint32_t def_addrs = 923;   // DEF_ADDRS_PER_INODE
    uint32_t addrs_per_block = 1018;
    uint32_t inid_off = 4052;   // byte offset of i_nid[0] in a node block
};

struct Ctx {
    Ctx(const Reader& r, SafeRoot& root, std::string subdir, Extracted& out)
        : r(r), root(root), subdir(std::move(subdir)), out(out) {}
    const Reader& r;
    Sb sb;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t inodes = 0;
    std::set<uint32_t> stack{};  // cycle guard on the directory path
};

std::optional<uint32_t> u32(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Little); }
std::optional<uint16_t> u16(const Reader& r, uint64_t o) { return r.at<uint16_t>(o, Endian::Little); }

uint64_t blk_off(const Sb& sb, uint32_t blk) { return sb.base + uint64_t(blk) * sb.bs; }

// Physical node block for a node id, via the NAT (journal overlay first, then the
// bitmap-selected NAT copy). 0 => no valid mapping.
uint32_t nat_ba(const Sb& sb, const Reader& r, uint32_t nid) {
    auto j = sb.nat_journal.find(nid);
    if (j != sb.nat_journal.end()) return j->second;
    const uint32_t blkidx = nid / sb.nat_entry_per_block;
    uint32_t copy = 0;
    if (!sb.nat_bitmap.empty()) {
        const size_t byte = blkidx >> 3;
        if (byte < sb.nat_bitmap.size() && ((sb.nat_bitmap[byte] >> (blkidx & 7)) & 1)) copy = 1;
    }
    const uint64_t off = blk_off(sb, sb.nat_blkaddr) + uint64_t(copy) * sb.nat_half_blocks * sb.bs +
                         uint64_t(blkidx) * sb.bs + uint64_t(nid % sb.nat_entry_per_block) * NAT_ENTRY_SIZE;
    auto ba = u32(r, off + 5);  // {u8 version, le32 ino, le32 block_addr}
    return ba ? *ba : 0;
}

// Absolute byte offset of an inode's node block. 0 => invalid.
uint64_t inode_off(const Sb& sb, const Reader& r, uint32_t nid, bool& ok) {
    uint32_t ba = nat_ba(sb, r, nid);
    ok = ba != 0 && ba != NEW_ADDR;
    return ok ? blk_off(sb, ba) : 0;
}

// Count of in-inode data pointers, byte offset of the first, and inline flags.
struct InodeHdr {
    uint16_t mode = 0;
    uint8_t inl = 0;
    uint64_t size = 0;
    uint32_t cur_addrs = 0;   // in-inode data slots before the i_nid trees
    uint64_t iaddr_base = 0;  // absolute offset of i_addr data region
    uint64_t io = 0;          // absolute offset of the inode node block
    bool compressed = false;  // i_flags & F2FS_COMPR_FL (regular files)
    uint8_t compr_algo = 0;   // i_compress_algorithm
    uint32_t cluster_size = 0;// 1 << i_log_cluster_size (0 if not compressed)
};

std::optional<InodeHdr> read_inode(Ctx& c, uint32_t nid) {
    bool ok = false;
    uint64_t io = inode_off(c.sb, c.r, nid, ok);
    if (!ok) return std::nullopt;
    auto mode = u16(c.r, io);
    auto inl_b = c.r.bytes(io + 3, 1);
    auto size = c.r.at<uint64_t>(io + 16, Endian::Little);
    if (!mode || !inl_b || !size) return std::nullopt;
    InodeHdr h;
    h.io = io;
    h.mode = *mode;
    h.inl = (*inl_b)[0];
    h.size = *size;
    uint32_t extra_isize = 0;
    if (h.inl & EXTRA_ATTR) {
        auto e = u16(c.r, io + 360);  // i_extra_isize
        if (!e) return std::nullopt;
        extra_isize = *e;
    }
    if (extra_isize > c.sb.def_addrs * 4) return std::nullopt;
    h.iaddr_base = io + 360 + extra_isize;
    // ADDRS_PER_INODE (f2fs): DEF_ADDRS - extra_isize/4 - inline-xattr slots. The
    // inline xattr sits at the end of the in-inode data region, so it lowers the
    // block index at which the direct-node trees begin.
    uint32_t inline_xattr = 0;
    if (c.sb.feature & FEATURE_FLEXIBLE_INLINE_XATTR) {
        if (h.inl & EXTRA_ATTR) {
            auto x = u16(c.r, io + 362);  // i_inline_xattr_size (in 4-byte units)
            inline_xattr = x ? *x : 0;
        }
    } else if (h.inl & (INLINE_XATTR | INLINE_DENTRY)) {
        inline_xattr = DEFAULT_INLINE_XATTR_ADDRS;
    }
    const uint32_t used = extra_isize / 4 + inline_xattr;
    h.cur_addrs = used < c.sb.def_addrs ? c.sb.def_addrs - used : 0;

    // Per-file compression: regular file with F2FS_COMPR_FL and an extra-attr area
    // large enough to carry i_compress_algorithm(@+32) / i_log_cluster_size(@+33).
    if ((h.mode & S_IFMT) == S_IFREG && (h.inl & EXTRA_ATTR) && extra_isize >= 36) {
        auto flags = u32(c.r, io + 80);  // i_flags
        if (flags && (*flags & F2FS_COMPR_FL)) {
            auto algo = c.r.bytes(io + 392, 1);   // i_compress_algorithm
            auto logcs = c.r.bytes(io + 393, 1);  // i_log_cluster_size
            if (algo && logcs && (*logcs)[0] <= 8) {
                h.compressed = true;
                h.compr_algo = (*algo)[0];
                h.cluster_size = 1u << (*logcs)[0];
                // For compressed regular files, the addresses-per-node count is
                // aligned down to the cluster size so a cluster never straddles a
                // node boundary (kernel addrs_per_page()).
                h.cur_addrs -= h.cur_addrs % h.cluster_size;
            }
        }
    }
    return h;
}

// Read the k-th data block address of an inode, resolving the direct/indirect/
// double-indirect node trees (each i_nid / indirect slot is itself a nid). 0 on
// any failure or hole.
uint32_t data_addr(Ctx& c, const InodeHdr& h, uint64_t bidx) {
    const Sb& sb = c.sb;
    if (bidx < h.cur_addrs) {
        auto a = u32(c.r, h.iaddr_base + bidx * 4);
        return a ? *a : 0;
    }
    uint64_t b = bidx - h.cur_addrs;
    // nids per (in)direct node is fixed; data addresses per *leaf* direct node is
    // aligned down to the cluster size for compressed files (see read_inode).
    const uint64_t npi = sb.addrs_per_block;
    const uint64_t dpd = h.compressed ? npi - (npi % h.cluster_size) : npi;

    auto inid = [&](int i) -> uint32_t {
        auto v = u32(c.r, h.io + sb.inid_off + uint64_t(i) * 4);
        return v ? *v : 0;
    };
    // The k-th entry of a direct node identified by nid.
    auto direct = [&](uint32_t node_nid, uint64_t k) -> uint32_t {
        if (node_nid == 0) return 0;
        uint32_t nba = nat_ba(sb, c.r, node_nid);
        if (nba == 0 || nba == NEW_ADDR) return 0;
        auto v = u32(c.r, blk_off(sb, nba) + k * 4);
        return v ? *v : 0;
    };
    // The k-th nid of an indirect node.
    auto indirect_nid = [&](uint32_t node_nid, uint64_t k) -> uint32_t {
        if (node_nid == 0) return 0;
        uint32_t nba = nat_ba(sb, c.r, node_nid);
        if (nba == 0 || nba == NEW_ADDR) return 0;
        auto v = u32(c.r, blk_off(sb, nba) + k * 4);
        return v ? *v : 0;
    };

    if (b < dpd) return direct(inid(0), b);
    b -= dpd;
    if (b < dpd) return direct(inid(1), b);
    b -= dpd;
    const uint64_t per_ind = npi * dpd;  // addrs reachable through one indirect node
    if (b < per_ind) return direct(indirect_nid(inid(2), b / dpd), b % dpd);
    b -= per_ind;
    if (b < per_ind) return direct(indirect_nid(inid(3), b / dpd), b % dpd);
    b -= per_ind;
    // double indirect (i_nid[4])
    if (b < npi * per_ind) {
        uint32_t l1 = indirect_nid(inid(4), b / per_ind);
        uint64_t r = b % per_ind;
        return direct(indirect_nid(l1, r / dpd), r % dpd);
    }
    return 0;
}

// Append the data block `ba` (or zeros for a hole) to `out`, up to `want` bytes.
bool append_block(Ctx& c, uint32_t ba, size_t want, std::vector<uint8_t>& out) {
    if (ba == NULL_ADDR || ba == NEW_ADDR) {
        out.insert(out.end(), want, 0);  // sparse hole
        return true;
    }
    auto d = c.r.bytes(static_cast<size_t>(blk_off(c.sb, ba)), c.sb.bs);
    if (!d) { c.truncated = true; return false; }
    out.insert(out.end(), d->begin(), d->begin() + want);
    return true;
}

// Read a per-file-compressed file, one cluster at a time. A cluster whose first
// block address is COMPRESS_ADDR is decompressed (compress_data header + codec
// bytes gathered from the cluster's real block addresses, decoded to one full
// cluster); any other cluster is stored raw and read block-by-block.
bool read_file_compressed(Ctx& c, const InodeHdr& h, uint64_t size, std::vector<uint8_t>& out) {
    const uint64_t bs = c.sb.bs;
    const uint32_t cs = h.cluster_size;
    const uint64_t full = uint64_t(cs) * bs;      // decompressed size of a full cluster
    const uint64_t nblk = (size + bs - 1) / bs;   // logical blocks in the file
    out.reserve(static_cast<size_t>(size));
    for (uint64_t cb = 0; cb < nblk; cb += cs) {
        const uint64_t cl_off = cb * bs;          // logical byte offset of this cluster
        if (data_addr(c, h, cb) == COMPRESS_ADDR) {
            std::vector<uint8_t> cbuf;
            cbuf.reserve(static_cast<size_t>(full));
            for (uint32_t j = 1; j < cs; ++j) {
                const uint32_t ba = data_addr(c, h, cb + j);
                if (ba == NULL_ADDR || ba == NEW_ADDR || ba == COMPRESS_ADDR) continue;
                auto d = c.r.bytes(static_cast<size_t>(blk_off(c.sb, ba)), bs);
                if (!d) { c.truncated = true; break; }
                cbuf.insert(cbuf.end(), d->begin(), d->end());
            }
            if (cbuf.size() < COMPRESS_HEADER_SIZE) { c.truncated = true; return !out.empty(); }
            const uint32_t clen = uint32_t(cbuf[0]) | (uint32_t(cbuf[1]) << 8) |
                                  (uint32_t(cbuf[2]) << 16) | (uint32_t(cbuf[3]) << 24);
            if (uint64_t(COMPRESS_HEADER_SIZE) + clen > cbuf.size()) {
                c.truncated = true;
                return !out.empty();
            }
            std::span<const uint8_t> cd(cbuf.data() + COMPRESS_HEADER_SIZE, clen);
            std::optional<std::vector<uint8_t>> dec;
            switch (h.compr_algo) {
                case COMPR_LZ4:  dec = lz4_block_exact(cd, static_cast<size_t>(full)); break;
                case COMPR_LZO:  dec = decompress(Compressor::Lzo, cd, static_cast<size_t>(full)); break;
                case COMPR_ZSTD: dec = decompress(Compressor::Zstd, cd, static_cast<size_t>(full)); break;
                case COMPR_LZORLE: dec = decompress(Compressor::LzoRle, cd, static_cast<size_t>(full)); break;
                default: dec = std::nullopt; break;
            }
            if (!dec) { c.truncated = true; return !out.empty(); }
            const uint64_t want = std::min<uint64_t>(full, size - cl_off);
            const size_t take = static_cast<size_t>(std::min<uint64_t>(want, dec->size()));
            out.insert(out.end(), dec->begin(), dec->begin() + take);
            if (take < want) c.truncated = true;
        } else {
            for (uint32_t j = 0; j < cs; ++j) {
                const uint64_t lb = cb + j;
                if (lb * bs >= size) break;
                const size_t want = static_cast<size_t>(std::min<uint64_t>(bs, size - lb * bs));
                if (!append_block(c, data_addr(c, h, lb), want, out)) return !out.empty();
            }
        }
    }
    return true;
}

// Read a whole file's bytes (inline or via the data-block tree).
bool read_file(Ctx& c, const InodeHdr& h, uint64_t cap, std::vector<uint8_t>& out) {
    uint64_t size = std::min<uint64_t>(h.size, cap);
    if (size > MAX_FILE_BYTES) { c.truncated = true; size = MAX_FILE_BYTES; }
    out.clear();
    if (size == 0) return true;
    if (h.compressed && h.cluster_size >= 2) return read_file_compressed(c, h, size, out);
    if (h.inl & INLINE_DATA) {
        // Inline data lives just past a single reserved slot in the inline area.
        auto d = c.r.bytes(static_cast<size_t>(h.iaddr_base + 4), static_cast<size_t>(size));
        if (!d) { c.truncated = true; return false; }
        out.assign(d->begin(), d->end());
        return true;
    }
    const uint64_t bs = c.sb.bs;
    const uint64_t nblk = (size + bs - 1) / bs;
    out.reserve(static_cast<size_t>(size));
    for (uint64_t k = 0; k < nblk; ++k) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(bs, size - k * bs));
        if (!append_block(c, data_addr(c, h, k), want, out)) return false;
    }
    return true;
}

struct Dentry {
    std::string name;
    uint32_t ino;
    uint8_t ftype;
};

// Parse a dentry region (bitmap + entries + names) into child entries.
void parse_dentries(std::span<const uint8_t> blk, uint32_t nr, uint32_t bitmap_sz, uint32_t reserved,
                    std::vector<Dentry>& out) {
    const uint32_t de_off = bitmap_sz + reserved;
    const uint32_t fn_off = de_off + nr * 11;
    if (uint64_t(fn_off) + uint64_t(nr) * 8 > blk.size()) return;
    for (uint32_t i = 0; i < nr;) {
        if (!((blk[i >> 3] >> (i & 7)) & 1)) { ++i; continue; }
        const uint8_t* de = blk.data() + de_off + i * 11;
        uint32_t ino;
        uint16_t name_len;
        std::memcpy(&ino, de + 4, 4);
        std::memcpy(&name_len, de + 8, 2);
        const uint8_t ftype = de[10];
        const uint32_t slots = std::max<uint32_t>(1, (name_len + 7) / 8);
        if (name_len == 0 || name_len > 255) { i += slots; continue; }
        const uint8_t* nm = blk.data() + fn_off + uint64_t(i) * 8;
        if (nm + name_len > blk.data() + blk.size()) { i += slots; continue; }
        std::string name(reinterpret_cast<const char*>(nm), name_len);
        if (name != "." && name != ".." && name.find('/') == std::string::npos &&
            name.find('\0') == std::string::npos)
            out.push_back({std::move(name), ino, ftype});
        i += slots;
    }
}

// Collect a directory's child entries (from inline dentries or dentry blocks).
void dir_entries(Ctx& c, const InodeHdr& h, std::vector<Dentry>& out) {
    const uint32_t bs = c.sb.bs;
    // per-block dentry geometry (constant for a block size)
    const uint32_t nr_blk = (8u * bs) / 153u;
    const uint32_t bmp_blk = (nr_blk + 7) / 8;
    const uint32_t reserved_blk = bs - (19u * nr_blk + bmp_blk);

    if (h.inl & INLINE_DENTRY) {
        // Inline dentry occupies the inline area (past one reserved slot).
        const uint32_t max_inline = (h.cur_addrs > 1) ? (h.cur_addrs - 1) * 4 : 0;
        const uint32_t nr = (max_inline * 8u) / 153u;
        if (nr == 0) return;
        const uint32_t bmp = (nr + 7) / 8;
        const uint32_t reserved = max_inline - (19u * nr + bmp);
        auto d = c.r.bytes(static_cast<size_t>(h.iaddr_base + 4), max_inline);
        if (!d) { c.truncated = true; return; }
        parse_dentries(*d, nr, bmp, reserved, out);
        return;
    }
    const uint64_t nblk = (h.size + bs - 1) / bs;
    for (uint64_t k = 0; k < nblk; ++k) {
        uint32_t ba = data_addr(c, h, k);
        if (ba == NULL_ADDR || ba == NEW_ADDR) continue;
        auto d = c.r.bytes(static_cast<size_t>(blk_off(c.sb, ba)), bs);
        if (!d) { c.truncated = true; continue; }
        parse_dentries(*d, nr_blk, bmp_blk, reserved_blk, out);
    }
}

void walk(Ctx& c, uint32_t nid, const std::string& rel, size_t depth);

void handle_child(Ctx& c, const Dentry& e, const std::string& rel, size_t depth) {
    const std::string child_rel = rel.empty() ? e.name : rel + "/" + e.name;
    const std::string full = c.subdir + "/" + child_rel;
    if (e.ftype == FT_DIR) {
        walk(c, e.ino, child_rel, depth + 1);
        return;
    }
    auto h = read_inode(c, e.ino);
    if (!h) { c.truncated = true; return; }
    if (e.ftype == FT_SYMLINK || (h->mode & S_IFMT) == S_IFLNK) {
        std::vector<uint8_t> t;
        if (read_file(c, *h, 4096, t)) {
            std::string target(t.begin(), t.end());
            if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
            if (!target.empty() && c.root.make_symlink(full, target)) c.out.symlinks++;
        }
        return;
    }
    if ((h->mode & S_IFMT) != 0 && (h->mode & S_IFMT) != 0100000) return;  // skip devices/fifos
    std::vector<uint8_t> data;
    if (read_file(c, *h, MAX_FILE_BYTES, data)) {
        if (c.root.write_file(full, data, h->mode & 0777)) {
            c.out.files++;
            c.out.bytes += data.size();
        } else {
            c.out.warnings.push_back("write failed: " + child_rel);
        }
    }
}

void walk(Ctx& c, uint32_t nid, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (c.inodes++ > MAX_INODES) { c.truncated = true; return; }
    auto h = read_inode(c, nid);
    if (!h) { c.truncated = true; return; }
    if ((h->mode & S_IFMT) != S_IFDIR) return;
    if (!rel.empty() && c.root.make_dir(c.subdir + "/" + rel)) c.out.dirs++;
    if (!c.stack.insert(nid).second) return;  // cycle guard
    std::vector<Dentry> entries;
    dir_entries(c, *h, entries);
    for (const auto& e : entries) handle_child(c, e, rel, depth);
    c.stack.erase(nid);
}

// Load the current checkpoint's NAT version bitmap and NAT journal into `sb`.
void load_checkpoint(Sb& sb, const Reader& r, uint32_t cp_blkaddr, uint32_t seg_count_nat) {
    const uint32_t blocks_per_seg = 1u << sb.log_blocks_per_seg;
    sb.nat_half_blocks = (uint64_t(seg_count_nat) << sb.log_blocks_per_seg) / 2;

    auto pack_ver = [&](uint32_t pack) -> std::optional<uint64_t> {
        auto ver = r.at<uint64_t>(blk_off(sb, pack), Endian::Little);
        auto total = u32(r, blk_off(sb, pack) + 136);
        if (!ver || !total || *total == 0 || *total > blocks_per_seg) return std::nullopt;
        auto foot = r.at<uint64_t>(blk_off(sb, pack + *total - 1), Endian::Little);
        if (!foot || *foot != *ver) return std::nullopt;
        return *ver;
    };
    uint32_t pack0 = cp_blkaddr, pack1 = cp_blkaddr + blocks_per_seg;
    auto v0 = pack_ver(pack0);
    auto v1 = pack_ver(pack1);
    uint32_t cur = pack0;
    if (v0 && v1)
        cur = (*v1 > *v0) ? pack1 : pack0;
    else if (v1 && !v0)
        cur = pack1;
    else if (!v0 && !v1)
        return;  // no valid checkpoint; nat_bitmap stays empty (copy 0 everywhere)

    const uint64_t o = blk_off(sb, cur);
    auto sit_b = u32(r, o + 156);
    auto nat_b = u32(r, o + 160);
    auto flags = u32(r, o + 132);
    auto start_sum = u32(r, o + 140);
    if (!sit_b || !nat_b || !flags || !start_sum) return;
    // NAT version bitmap follows the fixed 192-byte header and the SIT bitmap.
    if (*nat_b > 0 && *nat_b <= sb.bs) {
        auto bmp = r.bytes(static_cast<size_t>(o + 192 + *sit_b), *nat_b);
        if (bmp) sb.nat_bitmap.assign(bmp->begin(), bmp->end());
    }
    // NAT journal: hot-data summary block. Compact CPs pack it at offset 0,
    // normal CPs place it after the summary entries (offset bs - 512).
    const bool compact = (*flags & 0x4) != 0;
    const uint32_t sumblk = cur + *start_sum;
    const uint64_t jbase = blk_off(sb, sumblk) + (compact ? 0 : (sb.bs - 512));
    auto n_nats = u16(r, jbase);
    if (n_nats && *n_nats <= 512) {
        uint64_t p = jbase + 2;
        for (uint16_t i = 0; i < *n_nats; ++i, p += 13) {
            auto jnid = u32(r, p);
            auto jba = u32(r, p + 9);  // {le32 nid}{u8 ver, le32 ino, le32 block_addr}
            if (!jnid || !jba) continue;  // unset/deleted entry; keep scanning
            if (*jnid && *jba != NEW_ADDR) sb.nat_journal[*jnid] = *jba;
        }
    }
}

}  // namespace

bool extract_f2fs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out) {
    out.offset = f.offset;
    out.type = "f2fs";
    out.root = subdir;

    const uint64_t sbo = f.offset + SB_OFFSET;
    auto magic = u32(r, sbo);
    auto log_blocksize = u32(r, sbo + 16);
    auto log_blocks_per_seg = u32(r, sbo + 20);
    auto seg_count_nat = u32(r, sbo + 60);
    auto nat_blkaddr = u32(r, sbo + 84);
    auto root_ino = u32(r, sbo + 96);
    auto cp_blkaddr = u32(r, sbo + 76);
    auto feature = u32(r, sbo + 2180);
    if (!magic || *magic != F2FS_MAGIC || !log_blocksize || !log_blocks_per_seg || !seg_count_nat ||
        !nat_blkaddr || !root_ino || !cp_blkaddr) {
        out.status = "error:bad-superblock";
        return true;
    }
    if (*log_blocksize < 9 || *log_blocksize > 16 || *log_blocks_per_seg == 0 ||
        *log_blocks_per_seg > 24) {
        out.status = "error:bad-superblock";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    Ctx c(r, root, subdir, out);
    c.sb.base = f.offset;
    c.sb.log_bs = *log_blocksize;
    c.sb.bs = 1u << *log_blocksize;
    c.sb.log_blocks_per_seg = *log_blocks_per_seg;
    c.sb.nat_blkaddr = *nat_blkaddr;
    c.sb.root_ino = *root_ino;
    c.sb.feature = feature ? *feature : 0;
    c.sb.nat_entry_per_block = c.sb.bs / NAT_ENTRY_SIZE;
    c.sb.def_addrs = (c.sb.bs - 360 - 20 - 24) / 4;
    c.sb.addrs_per_block = (c.sb.bs - 24) / 4;
    c.sb.inid_off = c.sb.bs - 44;

    load_checkpoint(c.sb, r, *cp_blkaddr, *seg_count_nat);

    walk(c, c.sb.root_ino, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

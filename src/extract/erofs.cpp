// erofs.cpp — EROFS extraction. See erofs.hpp.
//
// Superblock @ base+1024 (LE): magic 0xE0F5E1E2 @0, blkszbits @12 (u8),
// root_nid @14 (u16), blocks @36, meta_blkaddr @40, feature_incompat @80.
// Inode @ base + meta_blkaddr*blocksize + nid*32. i_format @0: bit0 = extended
// (64B) else compact (32B); bits1..3 = datalayout. i_mode @4, i_size @8 (u32
// compact / u64 extended), i_u @16 (raw block addr for flat layouts). The inline
// tail / xattr area follows the inode: xattr_size = xic ? 12+(xic-1)*4 : 0.
// Directory data is blocks of 12-byte erofs_dirent {nid@0, nameoff@8, type@10};
// the first entry's nameoff / 12 gives the count, names run to the next nameoff.
//
// Compressed data (datalayout COMPRESSED_FULL / COMPRESSED_COMPACT): a per-inode
// z-map header sits at round_up(inode_end, 8) and describes the logical-cluster
// (lcluster) index that follows. Each lcluster is one of {PLAIN, HEAD1, HEAD2,
// NONHEAD}; a HEAD lcluster begins a physical cluster (pcluster) at its block
// address, and every following NONHEAD lcluster belongs to it. A pcluster's
// compressed data is one block (non-big-pcluster), decompressed to the logical
// span between this HEAD's start and the next HEAD's start (or EOF). We rebuild
// files by collecting the HEADs in order and decompressing each pcluster
// (lz4 / shifted-plain here; microlzma/deflate/zstd via the codec seam). The index
// comes in two on-disk forms: FULL (8-byte entries) and COMPACT (bit-packed 2B/
// 4B slots), both handled below. Range-checked throughout.
#include "extract/erofs.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "extract/decompress.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint32_t EROFS_MAGIC = 0xE0F5E1E2;
constexpr size_t SB_OFFSET = 1024;

// datalayout (i_format bits 1..3).
constexpr uint16_t LAYOUT_PLAIN = 0;
constexpr uint16_t LAYOUT_COMPRESSED_FULL = 1;
constexpr uint16_t LAYOUT_INLINE = 2;
constexpr uint16_t LAYOUT_COMPRESSED_COMPACT = 3;
constexpr uint16_t LAYOUT_CHUNK = 4;

// erofs_inode_chunk_info.format bits (i_u for chunk-based inodes)
constexpr uint16_t CHUNK_FORMAT_BLKBITS_MASK = 0x001F;
constexpr uint16_t CHUNK_FORMAT_INDEXES = 0x0020;
constexpr uint16_t CHUNK_FORMAT_48BIT = 0x0040;

// lcluster types (di_advise low 2 bits).
constexpr uint8_t LTYPE_PLAIN = 0;
constexpr uint8_t LTYPE_HEAD1 = 1;
constexpr uint8_t LTYPE_NONHEAD = 2;
constexpr uint8_t LTYPE_HEAD2 = 3;

// h_algorithmtype nibble values.
constexpr uint8_t ALG_LZ4 = 0;
constexpr uint8_t ALG_LZMA = 1;
constexpr uint8_t ALG_DEFLATE = 2;
constexpr uint8_t ALG_ZSTD = 3;

// z-map header h_advise bits.
constexpr uint16_t ADVISE_COMPACTED_2B = 0x0001;
constexpr uint16_t ADVISE_BIG_PCLUSTER_1 = 0x0002;
constexpr uint16_t ADVISE_BIG_PCLUSTER_2 = 0x0004;
constexpr uint16_t ADVISE_INLINE_PCLUSTER = 0x0008;
constexpr uint16_t ADVISE_INTERLACED_PCLUSTER = 0x0010;
constexpr uint16_t ADVISE_FRAGMENT_PCLUSTER = 0x0020;

constexpr uint16_t LI_D0_CBLKCNT = (1u << 11);  // big-pcluster block count flag
constexpr uint8_t FRAGMENT_INODE_BIT = 7;       // whole file in packed inode

constexpr uint16_t S_IFMT = 0170000;
constexpr uint16_t S_IFDIR = 0040000;
constexpr uint16_t S_IFREG = 0100000;
constexpr uint16_t S_IFLNK = 0120000;

constexpr size_t MAX_DEPTH = 128;
constexpr size_t MAX_INODES = 8000000;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;
constexpr uint64_t MAX_LCLUSTERS = (uint64_t(8) << 30) / 4096;  // per-file index cap

struct Super {
    uint64_t block_size = 4096;
    uint32_t blkszbits = 12;
    uint64_t meta_base = 0;  // absolute offset of the metadata (inode) area
    uint64_t packed_nid = 0; // nid of the special packed inode (fragments/dedupe)
    bool has_packed = false;
};

struct Inode {
    uint16_t mode = 0;
    uint64_t size = 0;
    uint16_t layout = 0;
    uint64_t raw_blk = 0;     // i_u: starting block for flat layouts
    uint64_t inline_off = 0;  // absolute offset of the inline tail
    uint64_t inode_end = 0;   // absolute offset just past inode + xattrs (unrounded)
};

struct Ctx {
    const Reader& r;
    uint64_t base;
    Super sb;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t inodes = 0;
    std::set<uint64_t> stack{};
    // Decoded packed inode (all fragment data concatenated), decoded lazily once.
    bool packed_done = false;
    bool packed_ok = false;
    std::vector<uint8_t> packed{};
};

std::optional<uint32_t> u32(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Little); }
std::optional<uint16_t> u16(const Reader& r, uint64_t o) { return r.at<uint16_t>(o, Endian::Little); }

std::optional<Inode> read_inode(Ctx& c, uint64_t nid) {
    const uint64_t io = c.sb.meta_base + nid * 32;
    auto fmt = u16(c.r, io);
    auto xic = u16(c.r, io + 2);
    auto mode = u16(c.r, io + 4);
    auto iu = u32(c.r, io + 16);
    if (!fmt || !xic || !mode || !iu) return std::nullopt;
    const bool extended = (*fmt & 1) != 0;
    const uint64_t isize = extended ? 64 : 32;
    Inode n;
    n.mode = *mode;
    n.layout = (*fmt >> 1) & 7;
    n.raw_blk = *iu;
    if (extended) {
        auto sz = c.r.at<uint64_t>(io + 8, Endian::Little);
        if (!sz) return std::nullopt;
        n.size = *sz;
    } else {
        auto sz = u32(c.r, io + 8);
        if (!sz) return std::nullopt;
        n.size = *sz;
    }
    const uint64_t xattr_size = *xic ? (12 + uint64_t(*xic - 1) * 4) : 0;
    n.inline_off = io + isize + xattr_size;
    n.inode_end = io + isize + xattr_size;
    return n;
}

// ---- compressed (COMPRESSED_FULL / COMPRESSED_COMPACT) support ----------------

struct ZInfo {
    uint16_t advise = 0;
    uint32_t lclusterbits = 12;
    uint8_t algo0 = 0, algo1 = 0;
    uint16_t idata_size = 0;    // tail-packing inline pcluster (encoded size)
    bool fragment = false;      // file (or its tail) lives in the packed inode
    bool whole_fragment = false;
    uint64_t fragmentoff = 0;   // byte offset into the decoded packed inode
    uint64_t header_pos = 0;    // absolute offset of the z-map header
    bool ok = false;
};

// One decoded lcluster index entry.
struct LClu {
    uint8_t type = LTYPE_NONHEAD;
    uint16_t clusterofs = 0;
    uint32_t blkaddr = 0;   // HEAD: physical block address
    uint16_t delta0 = 0;    // NONHEAD: distance back to HEAD
    uint32_t cblkcnt = 0;   // NONHEAD w/ CBLKCNT: big-pcluster block count
    bool cblk = false;
};

inline uint32_t get_le32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    if constexpr (std::endian::native == std::endian::big) v = byteswap_generic(v);
    return v;
}

std::optional<ZInfo> parse_zinfo(Ctx& c, const Inode& n) {
    ZInfo z;
    z.header_pos = (n.inode_end + 7) & ~uint64_t(7);
    auto h = c.r.bytes(static_cast<size_t>(z.header_pos), 8);
    if (!h) return std::nullopt;
    const uint8_t* p = h->data();
    const uint8_t clusterbits = p[7];
    if (clusterbits >> FRAGMENT_INODE_BIT) {  // whole file packed away
        // The 8-byte header, read as u64 with the top bit cleared, is the byte
        // offset of the whole file's data within the decoded packed inode.
        uint64_t hv;
        std::memcpy(&hv, p, 8);
        if constexpr (std::endian::native == std::endian::big) hv = byteswap_generic(hv);
        z.fragmentoff = hv & ~(uint64_t(1) << 63);
        z.whole_fragment = true;
        z.ok = true;
        return z;
    }
    uint16_t advise;
    std::memcpy(&advise, p + 4, 2);
    if constexpr (std::endian::native == std::endian::big) advise = byteswap_generic(advise);
    z.advise = advise;
    z.lclusterbits = c.sb.blkszbits + (clusterbits & 15);
    if (z.lclusterbits > 30) return std::nullopt;
    z.algo0 = p[6] & 15;
    z.algo1 = p[6] >> 4;
    if (z.advise & ADVISE_FRAGMENT_PCLUSTER) {
        z.fragment = true;
        z.fragmentoff = get_le32(p);  // h_fragmentoff (low 32 bits) at header start
    } else if (z.advise & ADVISE_INLINE_PCLUSTER) {
        std::memcpy(&z.idata_size, p + 2, 2);
        if constexpr (std::endian::native == std::endian::big)
            z.idata_size = byteswap_generic(z.idata_size);
    }
    z.ok = true;
    return z;
}

// Read a full-format 8-byte lcluster index entry at logical cluster `lcn`.
std::optional<LClu> load_full_lcluster(Ctx& c, const ZInfo& z, uint64_t lcn) {
    // FULL index starts at header_pos + sizeof(header)=8 + 8 (a reserved slot).
    const uint64_t pos = z.header_pos + 16 + lcn * 8;
    auto di_advise = u16(c.r, pos);
    auto clusterofs = u16(c.r, pos + 2);
    auto u = u32(c.r, pos + 4);
    if (!di_advise || !clusterofs || !u) return std::nullopt;
    LClu l;
    l.type = *di_advise & 3;
    if (l.type == LTYPE_NONHEAD) {
        l.delta0 = static_cast<uint16_t>(*u & 0xffff);
        if (l.delta0 & LI_D0_CBLKCNT) {
            l.cblk = true;
            l.cblkcnt = l.delta0 & ~LI_D0_CBLKCNT;
            l.delta0 = 1;
        }
    } else {
        l.clusterofs = *clusterofs;
        l.blkaddr = *u;
    }
    return l;
}

inline unsigned ilog2_u(unsigned x) { return x ? 31u - std::countl_zero(x) : 0u; }

// Decode `lobits`+2 packed bits at bit position `bitpos` within `in`.
uint32_t decode_compactedbits(unsigned lobits, const uint8_t* in, unsigned bitpos, uint8_t* type) {
    const uint32_t v = get_le32(in + bitpos / 8) >> (bitpos & 7);
    *type = static_cast<uint8_t>((v >> lobits) & 3);
    return v & ((1u << lobits) - 1);
}

// Read a compact-format lcluster index entry at logical cluster `lcn`.
// `totalidx` is the total lcluster count for the inode. Mirrors erofs-utils
// z_erofs_load_compact_lcluster (non-big-pcluster blkaddr recovery).
std::optional<LClu> load_compact_lcluster(Ctx& c, const ZInfo& z, uint64_t lcn, uint64_t totalidx) {
    const uint64_t ebase = z.header_pos + 8;  // just past the 8-byte header
    const unsigned lclusterbits = z.lclusterbits;
    if (lcn >= totalidx || lclusterbits > 14) return std::nullopt;
    const bool big1 = (z.advise & ADVISE_BIG_PCLUSTER_1) != 0;

    unsigned compacted_4b_initial = ((32 - ebase % 32) / 4) & 7;
    uint64_t compacted_2b = 0;
    if ((z.advise & ADVISE_COMPACTED_2B) && compacted_4b_initial < totalidx)
        compacted_2b = (totalidx - compacted_4b_initial) & ~uint64_t(15);  // rounddown 16

    uint64_t pos = ebase;
    unsigned amortizedshift = 2;  // compact 4b
    uint64_t rel = lcn;
    if (rel >= compacted_4b_initial) {
        pos += uint64_t(compacted_4b_initial) * 4;
        rel -= compacted_4b_initial;
        if (rel < compacted_2b) {
            amortizedshift = 1;
        } else {
            pos += compacted_2b * 2;
            rel -= compacted_2b;
        }
    }
    pos += rel << amortizedshift;

    unsigned vcnt;
    if ((1u << amortizedshift) == 4 && lclusterbits <= 14)
        vcnt = 2;
    else if ((1u << amortizedshift) == 2 && lclusterbits <= 12)
        vcnt = 16;
    else
        return std::nullopt;

    const unsigned packsz = vcnt << amortizedshift;
    const unsigned bytes = static_cast<unsigned>(pos & (packsz - 1));
    const uint64_t packpos = pos - bytes;
    auto pk = c.r.bytes(static_cast<size_t>(packpos), packsz);
    if (!pk) return std::nullopt;
    const uint8_t* in = pk->data();

    const unsigned lobits = std::max(lclusterbits, ilog2_u(LI_D0_CBLKCNT) + 1u);
    const unsigned encodebits = ((packsz - 4u) * 8u) >> ilog2_u(vcnt);
    int i = static_cast<int>(bytes >> amortizedshift);

    uint8_t type;
    uint32_t lo = decode_compactedbits(lobits, in, encodebits * i, &type);
    LClu l;
    l.type = type;
    if (type == LTYPE_NONHEAD) {
        if (lo & LI_D0_CBLKCNT) {
            l.cblk = true;
            l.cblkcnt = lo & ~LI_D0_CBLKCNT;
            l.delta0 = 1;
        } else if (i + 1 != static_cast<int>(vcnt)) {
            l.delta0 = static_cast<uint16_t>(lo);
        } else {
            // last slot of the pack stores delta[1]; recover delta[0] indirectly.
            uint32_t lo2 = decode_compactedbits(lobits, in, encodebits * (i - 1), &type);
            if (type != LTYPE_NONHEAD)
                lo2 = 0;
            else if (lo2 & LI_D0_CBLKCNT)
                lo2 = 1;
            l.delta0 = static_cast<uint16_t>(lo2 + 1);
        }
        return l;
    }
    l.clusterofs = static_cast<uint16_t>(lo);
    // Recover the HEAD block address: base blkaddr (last __le32 of the pack) plus
    // the number of preceding HEAD blocks in this pack (non-big-pcluster).
    unsigned nblk = 1;
    if (!big1) {
        while (i > 0) {
            --i;
            lo = decode_compactedbits(lobits, in, encodebits * i, &type);
            if (type == LTYPE_NONHEAD) i -= static_cast<int>(lo);
            if (i >= 0) ++nblk;
        }
    } else {
        nblk = 0;
        while (i > 0) {
            --i;
            lo = decode_compactedbits(lobits, in, encodebits * i, &type);
            if (type == LTYPE_NONHEAD) {
                if (lo & LI_D0_CBLKCNT) {
                    --i;
                    nblk += lo & ~LI_D0_CBLKCNT;
                    continue;
                }
                if (lo <= 1) return std::nullopt;
                i -= static_cast<int>(lo) - 2;
                continue;
            }
            ++nblk;
        }
    }
    l.blkaddr = get_le32(in + packsz - 4) + nblk;
    return l;
}

// Byte offset just past the compact pack that holds `lcn` (erofs nextpackoff),
// where a tail-packed inline pcluster begins.
bool compact_nextpackoff(const ZInfo& z, uint64_t lcn, uint64_t totalidx, uint64_t& out) {
    const uint64_t ebase = z.header_pos + 8;
    const unsigned lclusterbits = z.lclusterbits;
    if (lcn >= totalidx || lclusterbits > 14) return false;
    unsigned compacted_4b_initial = ((32 - ebase % 32) / 4) & 7;
    uint64_t compacted_2b = 0;
    if ((z.advise & ADVISE_COMPACTED_2B) && compacted_4b_initial < totalidx)
        compacted_2b = (totalidx - compacted_4b_initial) & ~uint64_t(15);
    uint64_t pos = ebase;
    unsigned amortizedshift = 2;
    uint64_t rel = lcn;
    if (rel >= compacted_4b_initial) {
        pos += uint64_t(compacted_4b_initial) * 4;
        rel -= compacted_4b_initial;
        if (rel < compacted_2b) {
            amortizedshift = 1;
        } else {
            pos += compacted_2b * 2;
            rel -= compacted_2b;
        }
    }
    pos += rel << amortizedshift;
    unsigned vcnt;
    if ((1u << amortizedshift) == 4 && lclusterbits <= 14)
        vcnt = 2;
    else if ((1u << amortizedshift) == 2 && lclusterbits <= 12)
        vcnt = 16;
    else
        return false;
    const uint64_t packsz = vcnt << amortizedshift;
    out = (pos & ~(packsz - 1)) + packsz;
    return true;
}

std::optional<LClu> load_lcluster(Ctx& c, const Inode& n, const ZInfo& z, uint64_t lcn,
                                  uint64_t totalidx) {
    if (n.layout == LAYOUT_COMPRESSED_COMPACT)
        return load_compact_lcluster(c, z, lcn, totalidx);
    return load_full_lcluster(c, z, lcn);
}

// Physical block count for the pcluster whose HEAD is at `lcn`. One block for a
// normal (non-big) pcluster; for a big-pcluster the count is carried as CBLKCNT
// on the first following NONHEAD lcluster.
uint64_t pcluster_blocks(Ctx& c, const Inode& n, const ZInfo& z, uint8_t htype, uint64_t lcn,
                         uint64_t totalidx, uint64_t lcsize) {
    const bool big = (htype == LTYPE_HEAD1 && (z.advise & ADVISE_BIG_PCLUSTER_1)) ||
                     ((htype == LTYPE_PLAIN || htype == LTYPE_HEAD2) &&
                      (z.advise & ADVISE_BIG_PCLUSTER_2));
    if (!big || (lcn + 1) * lcsize >= n.size) return 1;
    auto l = load_lcluster(c, n, z, lcn + 1, totalidx);
    if (l && l->type == LTYPE_NONHEAD && l->cblk && l->cblkcnt > 0)
        return std::min<uint64_t>(l->cblkcnt, 256);
    return 1;
}

// Decompress one pcluster (a raw block span already read) to exactly `llen`
// bytes at logical offset `start`. `htype` is the HEAD lcluster type.
bool decompress_pcluster(uint8_t htype, const ZInfo& z, std::span<const uint8_t> raw,
                         uint64_t start, uint64_t llen, uint64_t bs, std::vector<uint8_t>& piece) {
    if (htype == LTYPE_PLAIN) {
        // Uncompressed. INTERLACED rotates the block by the in-block offset.
        if (z.advise & ADVISE_INTERLACED_PCLUSTER) {
            if (raw.size() < bs) return false;
            const uint64_t skip = start & (bs - 1);
            const uint64_t rightpart = std::min<uint64_t>(bs - skip, llen);
            if (skip + rightpart > raw.size() || (llen - rightpart) > raw.size()) return false;
            piece.resize(static_cast<size_t>(llen));
            std::memcpy(piece.data(), raw.data() + skip, static_cast<size_t>(rightpart));
            std::memcpy(piece.data() + rightpart, raw.data(),
                        static_cast<size_t>(llen - rightpart));
            return true;
        }
        if (llen > raw.size()) return false;
        piece.assign(raw.begin(), raw.begin() + static_cast<size_t>(llen));
        return true;
    }
    const uint8_t alg = (htype == LTYPE_HEAD2) ? z.algo1 : z.algo0;
    // Strip erofs leading zero-padding before the codec stream.
    size_t margin = 0;
    while (margin < raw.size() && raw[margin] == 0) ++margin;
    if (margin >= raw.size()) return false;
    std::span<const uint8_t> in = raw.subspan(margin);
    std::optional<std::vector<uint8_t>> got;
    switch (alg) {
        case ALG_LZ4:
            got = lz4_block_exact(in, static_cast<size_t>(llen));
            break;
        case ALG_DEFLATE:
            got = decompress(Compressor::Deflate, in, static_cast<size_t>(llen));
            break;
        case ALG_ZSTD:
            got = decompress(Compressor::Zstd, in, static_cast<size_t>(llen));
            break;
        case ALG_LZMA:
            got = microlzma_block_exact(in, static_cast<size_t>(llen));
            break;
        default:
            return false;  // unknown algorithm
    }
    if (!got || got->size() != llen) return false;
    piece = std::move(*got);
    return true;
}

bool read_data(Ctx& c, const Inode& n, uint64_t cap, std::vector<uint8_t>& out);

// Decode the special packed inode (holds every file's fragment data concatenated)
// once, lazily. Returns the decoded bytes, or nullptr if there is no packed inode
// or it cannot be read. The packed inode is itself an ordinary (usually compressed)
// inode; it never carries the fragment advise, so this does not recurse.
const std::vector<uint8_t>* get_packed(Ctx& c) {
    if (c.packed_done) return c.packed_ok ? &c.packed : nullptr;
    c.packed_done = true;
    if (!c.sb.has_packed) return nullptr;
    auto pn = read_inode(c, c.sb.packed_nid);
    if (!pn) return nullptr;
    if (!read_data(c, *pn, pn->size, c.packed)) return nullptr;
    c.packed_ok = true;
    return &c.packed;
}

// Copy `len` bytes at `off` out of the decoded packed inode into `out` (appending).
// Returns false (and marks truncated) if the packed inode is missing or the slice
// runs past its end; copies whatever prefix is available.
bool append_fragment(Ctx& c, uint64_t off, uint64_t len, std::vector<uint8_t>& out) {
    const std::vector<uint8_t>* pk = get_packed(c);
    if (!pk) { c.truncated = true; return false; }
    if (off > pk->size()) { c.truncated = true; return false; }
    const uint64_t avail = std::min<uint64_t>(len, pk->size() - off);
    out.insert(out.end(), pk->begin() + static_cast<size_t>(off),
               pk->begin() + static_cast<size_t>(off + avail));
    if (avail < len) c.truncated = true;
    return avail > 0;
}

// Rebuild a compressed file's contents by walking its lcluster index, collecting
// HEAD lclusters (each starts a pcluster), and decompressing each pcluster to the
// logical span up to the next HEAD (or EOF). Returns false only when nothing at
// all was recovered; a partial result sets c.truncated and returns true.
bool read_data_compressed(Ctx& c, const Inode& n, uint64_t cap, std::vector<uint8_t>& out) {
    auto zo = parse_zinfo(c, n);
    out.clear();
    if (!zo || !zo->ok) { c.truncated = true; return false; }
    const ZInfo& z = *zo;

    uint64_t size = std::min<uint64_t>(n.size, cap);
    if (size > MAX_FILE_BYTES) { c.truncated = true; size = MAX_FILE_BYTES; }
    if (size == 0) return true;
    // Whole-file fragment: the entire file is a slice of the decoded packed inode.
    if (z.whole_fragment) {
        out.reserve(static_cast<size_t>(size));
        append_fragment(c, z.fragmentoff, size, out);
        return !out.empty();
    }
    // A tail fragment (z.fragment) has a normal compressed head followed by a tail
    // that lives in the packed inode; that is handled inside the head walk below.

    const uint64_t bs = c.sb.block_size;
    const uint64_t lcsize = uint64_t(1) << z.lclusterbits;
    const uint64_t totalidx = (n.size + lcsize - 1) / lcsize;
    if (totalidx == 0 || totalidx > MAX_LCLUSTERS) { c.truncated = true; return false; }

    struct Head {
        uint64_t start;
        uint8_t type;
        uint32_t blkaddr;
        uint64_t lcn;
    };
    std::vector<Head> heads;
    for (uint64_t lcn = 0; lcn < totalidx; ++lcn) {
        auto l = load_lcluster(c, n, z, lcn, totalidx);
        if (!l) { c.truncated = true; break; }
        if (l->type != LTYPE_NONHEAD)
            heads.push_back({lcn * lcsize + l->clusterofs, l->type, l->blkaddr, lcn});
    }
    if (heads.empty()) { c.truncated = true; return false; }

    // The final index entry is a zero-length PLAIN terminator at logical EOF; the
    // tail-packed inline pcluster belongs to the last HEAD that actually carries
    // bytes (start < i_size), not that terminator.
    size_t tail_k = heads.size();
    for (size_t k = 0; k < heads.size(); ++k)
        if (heads[k].start < n.size) tail_k = k;

    out.reserve(static_cast<size_t>(size));
    const bool tailpack = z.idata_size != 0;
    for (size_t k = 0; k < heads.size() && out.size() < size; ++k) {
        const uint64_t start = heads[k].start;
        const uint64_t end = (k + 1 < heads.size()) ? heads[k + 1].start : n.size;
        if (end <= start) continue;
        const uint64_t llen = end - start;

        // Tail fragment: the final logical span lives in the packed inode, not in
        // any compressed pcluster. Copy it straight out.
        if (z.fragment && k == tail_k) {
            append_fragment(c, z.fragmentoff, llen, out);
            continue;
        }

        std::span<const uint8_t> raw;
        std::optional<std::span<const uint8_t>> rawopt;
        if (tailpack && k == tail_k) {
            // Tail-packing: the last pcluster is stored inline just past the index
            // pack of the *final* lcluster ((i_size-1) >> lclusterbits), not the
            // tail HEAD's own lcluster (erofs computes this via GET_BLOCKS_FINDTAIL).
            const uint64_t last_lcn = (n.size - 1) >> z.lclusterbits;
            uint64_t ipos;
            if (n.layout == LAYOUT_COMPRESSED_COMPACT) {
                if (!compact_nextpackoff(z, last_lcn, totalidx, ipos)) { c.truncated = true; break; }
            } else {
                ipos = z.header_pos + 16 + (last_lcn + 1) * 8;
            }
            rawopt = c.r.bytes(static_cast<size_t>(ipos), z.idata_size);
        } else {
            const uint64_t nblocks = pcluster_blocks(c, n, z, heads[k].type, heads[k].lcn,
                                                     totalidx, lcsize);
            const uint64_t pa = c.base + uint64_t(heads[k].blkaddr) * bs;
            const uint64_t avail = pa < c.r.size() ? c.r.size() - pa : 0;
            const size_t rlen = static_cast<size_t>(std::min<uint64_t>(nblocks * bs, avail));
            rawopt = c.r.bytes(static_cast<size_t>(pa), rlen);
        }
        if (!rawopt) { c.truncated = true; break; }
        raw = *rawopt;

        std::vector<uint8_t> piece;
        if (!decompress_pcluster(heads[k].type, z, raw, start, llen, bs, piece)) {
            c.truncated = true;
            break;  // rest would be misaligned; keep what we have
        }
        out.insert(out.end(), piece.begin(), piece.end());
    }
    if (out.size() > size) out.resize(static_cast<size_t>(size));
    if (out.size() < size) c.truncated = true;
    return !out.empty();
}

// Read a file/dir/symlink's uncompressed data. Returns false for compressed
// layouts (not yet supported) or on overrun.
// CHUNK_BASED (layout 4): the file is split into fixed-size chunks; a chunk index
// (or a plain 4-byte block array) right after the inode maps each chunk to a
// starting block (NULL_ADDR => a hole of zeros).
bool read_data_chunked(Ctx& c, const Inode& n, uint64_t size, std::vector<uint8_t>& out) {
    const uint64_t bs = c.sb.block_size;
    // Chunk/hole data is read raw from blocks, so it cannot exceed the image; clamp
    // a corrupt i_size here so it cannot drive a huge hole zero-fill allocation.
    if (size > c.r.size()) { c.truncated = true; size = c.r.size(); }
    const uint16_t format = static_cast<uint16_t>(n.raw_blk & 0xFFFF);  // chunk_info.format
    const unsigned chunkbits = c.sb.blkszbits + (format & CHUNK_FORMAT_BLKBITS_MASK);
    if (chunkbits > 30) { c.truncated = true; return false; }
    const uint64_t chunksize = uint64_t(1) << chunkbits;
    const bool indexes = format & CHUNK_FORMAT_INDEXES;
    const bool bit48 = format & CHUNK_FORMAT_48BIT;
    const unsigned unit = indexes ? 8 : 4;
    const uint64_t idx_base = (n.inode_end + (unit - 1)) & ~uint64_t(unit - 1);
    const uint64_t nchunks = (size + chunksize - 1) / chunksize;
    out.reserve(static_cast<size_t>(size));
    for (uint64_t ci = 0; ci < nchunks; ++ci) {
        const uint64_t llen = std::min<uint64_t>(chunksize, size - ci * chunksize);
        uint64_t startblk;
        bool hole;
        if (indexes) {
            // erofs_inode_chunk_index { u16 startblk_hi; u16 device_id; u32 startblk_lo }
            auto hi = u16(c.r, idx_base + ci * 8);
            auto lo = u32(c.r, idx_base + ci * 8 + 4);
            if (!hi || !lo) { c.truncated = true; break; }
            const uint64_t addrmask = bit48 ? ((uint64_t(1) << 48) - 1) : 0xFFFFFFFFull;
            startblk = ((uint64_t(*hi) << 32) | *lo) & addrmask;
            hole = startblk == addrmask;  // NULL_ADDR (all bits set within the mask)
        } else {
            auto b = u32(c.r, idx_base + ci * 4);
            if (!b) { c.truncated = true; break; }
            startblk = *b;
            hole = startblk == 0xFFFFFFFFu;  // NULL_ADDR
        }
        if (hole) {
            out.insert(out.end(), static_cast<size_t>(llen), 0);
        } else {
            auto d = c.r.bytes(static_cast<size_t>(c.base + startblk * bs), static_cast<size_t>(llen));
            if (!d) { c.truncated = true; break; }
            out.insert(out.end(), d->begin(), d->end());
        }
    }
    return !out.empty();
}

bool read_data(Ctx& c, const Inode& n, uint64_t cap, std::vector<uint8_t>& out) {
    uint64_t size = std::min<uint64_t>(n.size, cap);
    if (size > MAX_FILE_BYTES) { c.truncated = true; size = MAX_FILE_BYTES; }
    out.clear();
    if (size == 0) return true;
    const uint64_t bs = c.sb.block_size;

    if (n.layout == LAYOUT_CHUNK) return read_data_chunked(c, n, size, out);
    if (n.layout == LAYOUT_PLAIN) {
        auto d = c.r.bytes(static_cast<size_t>(c.base + n.raw_blk * bs), static_cast<size_t>(size));
        if (!d) { c.truncated = true; return false; }
        out.assign(d->begin(), d->end());
        return true;
    }
    if (n.layout == LAYOUT_INLINE) {
        const uint64_t full = size / bs;      // full blocks live at raw_blk
        const uint64_t tail = size - full * bs;  // last partial block is inline
        if (full) {
            auto d = c.r.bytes(static_cast<size_t>(c.base + n.raw_blk * bs),
                               static_cast<size_t>(full * bs));
            if (!d) { c.truncated = true; return false; }
            out.insert(out.end(), d->begin(), d->end());
        }
        if (tail) {
            auto d = c.r.bytes(static_cast<size_t>(n.inline_off), static_cast<size_t>(tail));
            if (!d) { c.truncated = true; return false; }
            out.insert(out.end(), d->begin(), d->end());
        }
        return true;
    }
    if (n.layout == LAYOUT_COMPRESSED_FULL || n.layout == LAYOUT_COMPRESSED_COMPACT)
        return read_data_compressed(c, n, cap, out);
    c.truncated = true;  // CHUNK_BASED: not yet handled
    return false;
}

void walk(Ctx& c, uint64_t nid, const std::string& rel, size_t depth);

// Decode one directory data block (self-contained erofs_dirent array + names).
void walk_dirblock(Ctx& c, const std::vector<uint8_t>& blk, const std::string& rel, size_t depth) {
    if (blk.size() < 12) return;
    uint16_t first_no;
    std::memcpy(&first_no, blk.data() + 8, 2);
    const uint32_t count = first_no / 12;
    if (count == 0 || uint64_t(count) * 12 > blk.size()) return;
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t enid;
        uint16_t nameoff;
        std::memcpy(&enid, blk.data() + i * 12, 8);
        std::memcpy(&nameoff, blk.data() + i * 12 + 8, 2);
        uint16_t name_end;
        if (i + 1 < count)
            std::memcpy(&name_end, blk.data() + (i + 1) * 12 + 8, 2);
        else
            name_end = static_cast<uint16_t>(std::min<size_t>(blk.size(), 0xffff));
        if (nameoff > blk.size() || name_end > blk.size() || name_end < nameoff) continue;
        std::string name(reinterpret_cast<const char*>(blk.data() + nameoff), name_end - nameoff);
        if (auto z = name.find('\0'); z != std::string::npos) name.resize(z);
        if (name.empty() || name == "." || name == ".." ||
            name.find('/') != std::string::npos)
            continue;
        walk(c, enid, rel.empty() ? name : rel + "/" + name, depth + 1);
    }
}

void walk(Ctx& c, uint64_t nid, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (c.inodes++ > MAX_INODES) { c.truncated = true; return; }
    auto ni = read_inode(c, nid);
    if (!ni) { c.truncated = true; return; }
    const Inode& n = *ni;
    const uint16_t type = n.mode & S_IFMT;
    const std::string full = c.subdir + (rel.empty() ? "" : "/" + rel);

    if (type == S_IFDIR) {
        if (!rel.empty() && c.root.make_dir(full)) c.out.dirs++;
        if (!c.stack.insert(nid).second) return;  // cycle guard
        std::vector<uint8_t> data;
        if (read_data(c, n, uint64_t(64) << 20, data)) {
            const uint64_t bs = c.sb.block_size;
            for (uint64_t off = 0; off < data.size(); off += bs) {
                std::vector<uint8_t> blk(data.begin() + off,
                                         data.begin() + std::min<uint64_t>(off + bs, data.size()));
                walk_dirblock(c, blk, rel, depth);
            }
        }
        c.stack.erase(nid);
    } else if (type == S_IFLNK) {
        std::vector<uint8_t> t;
        if (read_data(c, n, 4096, t)) {
            std::string target(t.begin(), t.end());
            if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
            if (!target.empty() && c.root.make_symlink(full, target)) c.out.symlinks++;
        }
    } else if (type == S_IFREG) {
        std::vector<uint8_t> data;
        if (read_data(c, n, MAX_FILE_BYTES, data)) {
            if (c.root.write_file(full, data, n.mode & 0777)) {
                c.out.files++;
                c.out.bytes += data.size();
            } else {
                c.out.warnings.push_back("write failed: " + rel);
            }
        }
    }
}

}  // namespace

bool extract_erofs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out) {
    out.offset = f.offset;
    out.type = "erofs";
    out.root = subdir;

    const uint64_t sbo = f.offset + SB_OFFSET;
    auto magic = u32(r, sbo);
    auto blkszbits = r.bytes(sbo + 12, 1);
    auto root_nid = u16(r, sbo + 14);
    auto meta_blkaddr = u32(r, sbo + 40);
    auto feat_incompat = u32(r, sbo + 80);
    auto packed_nid = r.at<uint64_t>(sbo + 96, Endian::Little);
    if (!magic || *magic != EROFS_MAGIC || !blkszbits || !root_nid || !meta_blkaddr) {
        out.status = "error:bad-superblock";
        return true;
    }
    const uint8_t bb = (*blkszbits)[0];
    if (bb < 9 || bb > 16) {
        out.status = "error:bad-superblock";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    Ctx c{r, f.offset, {}, root, subdir, out};
    c.sb.block_size = uint64_t(1) << bb;
    c.sb.blkszbits = bb;
    c.sb.meta_base = f.offset + uint64_t(*meta_blkaddr) * c.sb.block_size;
    // FRAGMENTS/DEDUPE feature (0x20) => a special packed inode holds fragment data.
    if (feat_incompat && (*feat_incompat & 0x20) && packed_nid && *packed_nid) {
        c.sb.packed_nid = *packed_nid;
        c.sb.has_packed = true;
    }

    walk(c, *root_nid, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

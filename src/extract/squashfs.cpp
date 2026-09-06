// squashfs.cpp — SquashFS v4.0 extraction. See squashfs.hpp.
//
// Format reference: https://dr-emann.github.io/squashfs/
// v4 is normally little-endian ("hsqs"), but genuine big-endian images ("sqsh")
// store every field big-endian; the parser is endian-aware throughout (Ctx.endian
// is set from the magic form). Reads from the source image go through the
// bounds-checked Reader; metadata/data blocks are decompressed with a bounded
// output cap; writes go through SafeRoot (openat + O_NOFOLLOW). Hostile headers
// yield truncated/partial output, never OOB reads or writes outside the root.
#include "extract/squashfs.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "byteorder.hpp"
#include "extract/decompress.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr size_t METADATA_MAX = 8192;
constexpr uint32_t FRAG_NONE = 0xffffffff;
constexpr uint32_t BLOCK_UNCOMPRESSED = 1u << 24;  // flag in a data block size
constexpr size_t META_UNCOMPRESSED = 0x8000;       // flag in a metadata block header

// Guardrails against hostile / corrupt images.
constexpr size_t MAX_FILES = 500000;
constexpr size_t MAX_DEPTH = 100;
constexpr size_t MAX_ENTRIES_PER_HEADER = 256;  // format cap
constexpr size_t MAX_METABUF = 64 * 1024 * 1024;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;  // 8 GiB per file

// Endian-aware reads out of a decompressed metadata buffer. v4 images are almost
// always little-endian ("hsqs"), but genuine big-endian images ("sqsh") store
// every field big-endian, so the whole metadata path is parameterized by endian.
inline uint16_t rd16(const uint8_t* p, Endian e) { return load_u16(p, e); }
inline uint32_t rd32(const uint8_t* p, Endian e) { return load_u32(p, e); }
inline uint64_t rd64(const uint8_t* p, Endian e) { return load_u64(p, e); }

struct Super {
    uint32_t inodes = 0;
    uint32_t block_size = 0;
    uint32_t fragments = 0;
    uint16_t compression = 0;
    uint16_t block_log = 0;
    uint16_t s_major = 0;
    uint64_t root_inode = 0;
    uint64_t bytes_used = 0;
    uint64_t inode_table_start = 0;
    uint64_t directory_table_start = 0;
    uint64_t fragment_table_start = 0;
};

struct Ctx {
    const Reader& r;
    size_t base;  // absolute file offset of the squashfs superblock
    Super sb;
    Compressor comp;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    Endian endian = Endian::Little;  // field byte order (hsqs=LE, sqsh=BE)
    uint64_t byte_budget = 0;  // cap on total bytes written (anti-bomb)
    bool truncated = false;    // hit a guardrail; results are partial
    // A compressed block had valid framing (in-range metadata length or block
    // size) but the payload would not decompress. When this is set and nothing
    // was recovered, the image is structurally a squashfs whose compressed data
    // is undecodable - the fingerprint of vendor payload obfuscation/encryption.
    bool decode_failed_valid_frame = false;
};

// A cursor over a metadata stream: decompresses successive metadata blocks
// on demand and concatenates, so a struct spanning a block boundary reads
// transparently. Absolute file position of the next block is `pos`.
struct MetaReader {
    Ctx& c;
    size_t pos;
    std::vector<uint8_t> buf;
    size_t idx = 0;

    MetaReader(Ctx& ctx, size_t start) : c(ctx), pos(start) {}

    bool read_one_block() {
        auto hdr = c.r.at<uint16_t>(pos, c.endian);
        if (!hdr) return false;
        size_t size = *hdr & 0x7fff;
        bool uncompressed = (*hdr & META_UNCOMPRESSED) != 0;
        if (size == 0 || size > METADATA_MAX * 2) return false;
        auto data = c.r.bytes(pos + 2, size);
        if (!data) return false;
        pos += 2 + size;
        if (uncompressed) {
            if (size > METADATA_MAX) return false;
            buf.insert(buf.end(), data->begin(), data->end());
        } else {
            auto d = decompress(c.comp, *data, METADATA_MAX);
            if (!d) {
                c.decode_failed_valid_frame = true;  // valid header, payload won't decode
                return false;
            }
            buf.insert(buf.end(), d->begin(), d->end());
        }
        return buf.size() <= MAX_METABUF;
    }

    bool ensure(size_t n) {
        while (buf.size() - idx < n) {
            if (!read_one_block()) return false;
        }
        return true;
    }
    bool skip(size_t n) {
        if (!ensure(n)) return false;
        idx += n;
        return true;
    }
    bool get16(uint16_t& v) {
        if (!ensure(2)) return false;
        v = rd16(buf.data() + idx, c.endian);
        idx += 2;
        return true;
    }
    bool get32(uint32_t& v) {
        if (!ensure(4)) return false;
        v = rd32(buf.data() + idx, c.endian);
        idx += 4;
        return true;
    }
    bool get64(uint64_t& v) {
        if (!ensure(8)) return false;
        v = rd64(buf.data() + idx, c.endian);
        idx += 8;
        return true;
    }
    bool getstr(std::string& s, size_t n) {
        if (!ensure(n)) return false;
        s.assign(reinterpret_cast<const char*>(buf.data() + idx), n);
        idx += n;
        return true;
    }
};

// Parsed inode: only the fields extraction needs.
struct Inode {
    uint16_t type = 0;
    uint16_t mode = 0;
    // file
    uint64_t blocks_start = 0;
    uint64_t file_size = 0;
    uint32_t fragment = FRAG_NONE;
    uint32_t frag_offset = 0;
    std::vector<uint32_t> block_sizes;
    // dir
    uint32_t dir_start_block = 0;
    uint32_t dir_offset = 0;
    uint32_t dir_size = 0;
    // symlink
    std::string symlink_target;
};

bool parse_super(Ctx& c) {
    const Reader& r = c.r;
    size_t b = c.base;
    auto m4 = r.bytes(b, 4);
    if (!m4) return false;
    auto eq = [&](const char* s) { return std::memcmp(m4->data(), s, 4) == 0; };
    // Little-endian body: standard "hsqs" plus modified-magic variants (TP-Link/
    // Broadcom "shsq", "hsqt"). Big-endian body: canonical "sqsh" plus its
    // modified-magic variants (qshs/tqsh/sqlz). Vendors alter the 4-byte magic to
    // defeat stock unsquashfs; the endianness follows the magic form.
    if (eq("hsqs") || eq("shsq") || eq("hsqt"))
        c.endian = Endian::Little;
    else if (eq("sqsh") || eq("qshs") || eq("tqsh") || eq("sqlz"))
        c.endian = Endian::Big;
    else
        return false;
    const Endian e = c.endian;
    auto g16 = [&](size_t off) { return r.at<uint16_t>(b + off, e).value_or(0); };
    auto g32 = [&](size_t off) { return r.at<uint32_t>(b + off, e).value_or(0); };
    auto g64 = [&](size_t off) { return r.at<uint64_t>(b + off, e).value_or(0); };
    Super& s = c.sb;
    s.inodes = g32(4);
    s.block_size = g32(12);
    s.fragments = g32(16);
    s.compression = g16(20);
    s.block_log = g16(22);
    s.s_major = g16(28);
    s.root_inode = g64(32);
    s.bytes_used = g64(40);
    s.inode_table_start = g64(64);
    s.directory_table_start = g64(72);
    s.fragment_table_start = g64(80);
    if (s.s_major != 4) return false;
    if (s.block_log < 12 || s.block_log > 20) return false;
    if (s.block_size != (1u << s.block_log)) return false;
    return true;
}

// The superblock compression field is not always honest: some vendors ship an
// LZMA1 squashfs but leave the field set to gzip. Probe the first inode-table
// metadata block against candidate codecs and return the one that actually
// decodes it, preferring the declared codec so normal images are unchanged.
Compressor detect_compressor(Ctx& c) {
    Compressor declared = static_cast<Compressor>(c.sb.compression);
    auto hdr = c.r.at<uint16_t>(c.base + c.sb.inode_table_start, c.endian);
    if (!hdr) return declared;
    size_t size = *hdr & 0x7fff;
    if ((*hdr & META_UNCOMPRESSED) || size == 0 || size > METADATA_MAX) return declared;
    auto blk = c.r.bytes(c.base + c.sb.inode_table_start + 2, size);
    if (!blk) return declared;
    const Compressor cands[] = {declared,      Compressor::Xz,  Compressor::Lzma, Compressor::Gzip,
                                Compressor::Lzo, Compressor::Lz4, Compressor::Zstd};
    for (Compressor cand : cands)
        if (compressor_supported(cand) && decompress(cand, *blk, METADATA_MAX)) return cand;
    return declared;
}

// Read the inode at `ref` (block<<16 | offset within decompressed block).
bool read_inode(Ctx& c, uint64_t ref, Inode& node) {
    size_t block = static_cast<size_t>(ref >> 16);
    size_t offset = static_cast<size_t>(ref & 0xffff);
    MetaReader mr{c, c.base + c.sb.inode_table_start + block};
    if (!mr.skip(offset)) return false;

    uint16_t type, mode, uid, gid;
    uint32_t mtime, inode_no;
    if (!mr.get16(type) || !mr.get16(mode) || !mr.get16(uid) || !mr.get16(gid) ||
        !mr.get32(mtime) || !mr.get32(inode_no))
        return false;
    node.type = type;
    node.mode = mode;

    switch (type) {
        case 1: {  // basic directory
            uint32_t start_block, nlink;
            uint16_t size, off;
            uint32_t parent;
            if (!mr.get32(start_block) || !mr.get32(nlink) || !mr.get16(size) || !mr.get16(off) ||
                !mr.get32(parent))
                return false;
            node.dir_start_block = start_block;
            node.dir_offset = off;
            node.dir_size = size;
            return true;
        }
        case 8: {  // extended directory
            uint32_t nlink, size, start_block, parent, xattr;
            uint16_t icount, off;
            if (!mr.get32(nlink) || !mr.get32(size) || !mr.get32(start_block) ||
                !mr.get32(parent) || !mr.get16(icount) || !mr.get16(off) || !mr.get32(xattr))
                return false;
            node.dir_start_block = start_block;
            node.dir_offset = off;
            node.dir_size = size;
            return true;
        }
        case 2: {  // basic file
            uint32_t start_block, frag, foff, fsize;
            if (!mr.get32(start_block) || !mr.get32(frag) || !mr.get32(foff) || !mr.get32(fsize))
                return false;
            node.blocks_start = start_block;
            node.fragment = frag;
            node.frag_offset = foff;
            node.file_size = fsize;
            break;
        }
        case 9: {  // extended file
            uint64_t start_block, fsize, sparse;
            uint32_t nlink, frag, foff, xattr;
            if (!mr.get64(start_block) || !mr.get64(fsize) || !mr.get64(sparse) ||
                !mr.get32(nlink) || !mr.get32(frag) || !mr.get32(foff) || !mr.get32(xattr))
                return false;
            node.blocks_start = start_block;
            node.fragment = frag;
            node.frag_offset = foff;
            node.file_size = fsize;
            break;
        }
        case 3:    // basic symlink
        case 10: {  // extended symlink
            uint32_t nlink, tgt_size;
            if (!mr.get32(nlink) || !mr.get32(tgt_size)) return false;
            if (tgt_size > 65536) return false;
            if (!mr.getstr(node.symlink_target, tgt_size)) return false;
            return true;
        }
        default:
            // device/fifo/socket and their extended forms: nothing to write.
            return true;
    }

    // Files: read the block-size list.
    if (node.file_size > MAX_FILE_BYTES) return false;
    size_t nblocks;
    if (node.fragment == FRAG_NONE)
        nblocks = (node.file_size + c.sb.block_size - 1) / c.sb.block_size;
    else
        nblocks = node.file_size / c.sb.block_size;
    node.block_sizes.reserve(nblocks);
    for (size_t i = 0; i < nblocks; ++i) {
        uint32_t bs;
        if (!mr.get32(bs)) return false;
        node.block_sizes.push_back(bs);
    }
    return true;
}

// Locate the fragment entry `index`: (start, on-disk size, uncompressed?).
bool read_fragment_entry(Ctx& c, uint32_t index, uint64_t& start, uint32_t& size, bool& uncomp) {
    // Indirect: fragment_table_start is an array of u64 pointers to metadata
    // blocks, each holding up to 512 fragment entries (16 bytes each).
    size_t block_index = index / 512;
    size_t entry_in_block = index % 512;
    auto ptr = c.r.at<uint64_t>(c.base + c.sb.fragment_table_start + block_index * 8, c.endian);
    if (!ptr) return false;
    MetaReader mr{c, c.base + *ptr};
    if (!mr.skip(entry_in_block * 16)) return false;
    uint64_t frag_start;
    uint32_t frag_size, unused;
    if (!mr.get64(frag_start) || !mr.get32(frag_size) || !mr.get32(unused)) return false;
    start = frag_start;
    size = frag_size & 0xffffff;
    uncomp = (frag_size & BLOCK_UNCOMPRESSED) != 0;
    return true;
}

// Assemble a file's contents (data blocks + fragment tail) into `contents`.
bool read_file_data(Ctx& c, const Inode& node, std::vector<uint8_t>& contents) {
    // A hostile inode can claim a huge file built from sparse (zero-cost)
    // blocks; cap the running total against a global budget and reserve only a
    // bounded amount up front so the claim alone can't exhaust memory.
    uint64_t spent = c.out.bytes;
    if (spent + node.file_size > c.byte_budget) { c.truncated = true; return false; }
    contents.reserve(std::min<size_t>(static_cast<size_t>(node.file_size), 16u << 20));
    size_t dpos = c.base + node.blocks_start;
    uint64_t remaining = node.file_size;
    for (uint32_t bs : node.block_sizes) {
        size_t on_disk = bs & 0xffffff;
        bool uncompressed = (bs & BLOCK_UNCOMPRESSED) != 0;
        size_t want = remaining < c.sb.block_size ? static_cast<size_t>(remaining) : c.sb.block_size;
        if (on_disk == 0) {
            // Sparse block: a full block of zeros.
            contents.insert(contents.end(), want, 0);
        } else {
            auto data = c.r.bytes(dpos, on_disk);
            if (!data) return false;
            if (uncompressed) {
                contents.insert(contents.end(), data->begin(), data->end());
            } else {
                auto d = decompress(c.comp, *data, c.sb.block_size);
                if (!d) return false;
                contents.insert(contents.end(), d->begin(), d->end());
            }
            dpos += on_disk;
        }
        remaining -= want;
    }
    // Fragment tail.
    if (node.fragment != FRAG_NONE && remaining > 0) {
        uint64_t fstart;
        uint32_t fsize;
        bool funcomp;
        if (!read_fragment_entry(c, node.fragment, fstart, fsize, funcomp)) return false;
        auto data = c.r.bytes(c.base + fstart, fsize);
        if (!data) return false;
        std::vector<uint8_t> fragblk;
        if (funcomp) {
            fragblk.assign(data->begin(), data->end());
        } else {
            auto d = decompress(c.comp, *data, c.sb.block_size);
            if (!d) return false;
            fragblk = std::move(*d);
        }
        size_t tail = static_cast<size_t>(remaining);
        if (node.frag_offset + tail > fragblk.size()) return false;
        contents.insert(contents.end(), fragblk.begin() + node.frag_offset,
                        fragblk.begin() + node.frag_offset + tail);
    }
    return contents.size() == node.file_size;
}

// Depth-first walk. `rel` is the path (under subdir) of the inode at `ref`.
void walk(Ctx& c, uint64_t ref, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (c.out.files + c.out.dirs + c.out.symlinks > MAX_FILES) { c.truncated = true; return; }

    Inode node;
    if (!read_inode(c, ref, node)) { c.truncated = true; return; }

    switch (node.type) {
        case 1:
        case 8: {  // directory
            if (!c.root.make_dir(c.subdir + "/" + rel) && !rel.empty()) return;
            c.out.dirs++;
            // Read the directory listing from the directory table.
            MetaReader dr{c, c.base + c.sb.directory_table_start + node.dir_start_block};
            if (!dr.skip(node.dir_offset)) { c.truncated = true; return; }
            size_t listing = node.dir_size >= 3 ? node.dir_size - 3 : 0;
            size_t start_idx = dr.idx;
            while (dr.idx - start_idx < listing) {
                uint32_t count, entry_block, inode_base;
                if (!dr.get32(count) || !dr.get32(entry_block) || !dr.get32(inode_base)) {
                    c.truncated = true;
                    return;
                }
                size_t entries = static_cast<size_t>(count) + 1;
                if (entries > MAX_ENTRIES_PER_HEADER) { c.truncated = true; return; }
                for (size_t e = 0; e < entries; ++e) {
                    uint16_t eoff, etype, name_size;
                    uint16_t inode_delta_raw;
                    if (!dr.get16(eoff) || !dr.get16(inode_delta_raw) || !dr.get16(etype) ||
                        !dr.get16(name_size)) {
                        c.truncated = true;
                        return;
                    }
                    std::string name;
                    if (!dr.getstr(name, static_cast<size_t>(name_size) + 1)) {
                        c.truncated = true;
                        return;
                    }
                    if (name == "." || name == ".." || name.empty()) continue;
                    uint64_t child_ref = (uint64_t(entry_block) << 16) | eoff;
                    std::string child_rel = rel.empty() ? name : rel + "/" + name;
                    walk(c, child_ref, child_rel, depth + 1);
                }
            }
            return;
        }
        case 2:
        case 9: {  // file
            if (c.out.bytes + node.file_size > c.byte_budget) {
                c.out.warnings.push_back("skipped (exceeds size budget): " + rel);
                c.truncated = true;
                return;
            }
            std::vector<uint8_t> contents;
            if (!read_file_data(c, node, contents)) {
                c.out.warnings.push_back("file not fully recovered: " + rel);
                c.truncated = true;
                return;
            }
            // Preserve mode bits but guarantee the analyst can read the file
            // (squashfs may carry exec-only 0111 binaries; force owner rw).
            if (c.root.write_file(c.subdir + "/" + rel, contents, node.mode | 0600)) {
                c.out.files++;
                c.out.bytes += contents.size();
            } else {
                c.out.warnings.push_back("write failed: " + rel);
            }
            return;
        }
        case 3:
        case 10: {  // symlink
            if (c.root.make_symlink(c.subdir + "/" + rel, node.symlink_target))
                c.out.symlinks++;
            return;
        }
        default:
            return;  // special files: counted implicitly by omission
    }
}

}  // namespace

bool extract_squashfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                      Extracted& out) {
    out.offset = f.offset;
    out.type = "squashfs";
    out.root = subdir;

    Ctx c{r, f.offset, {}, Compressor::Unknown, root, subdir, out};
    if (!parse_super(c)) {
        out.status = "error:bad-superblock";
        return true;
    }
    // Total-output budget: generous vs the compressed size (real firmware
    // rarely exceeds a few x) but bounded, so a tiny crafted image can't force
    // a multi-GiB write. Floor keeps small legit images working.
    c.byte_budget = std::max<uint64_t>(uint64_t(2) << 30, uint64_t(c.sb.bytes_used) * 256);
    c.comp = detect_compressor(c);  // trust the payload, not a possibly-lying field
    if (!compressor_supported(c.comp)) {
        out.status = "unsupported:" + std::string(compressor_name(c.comp));
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    walk(c, c.sb.root_inode, "", 0);

    // Nothing recovered from a structurally valid squashfs. Probe the inode
    // table's first metadata block directly: a genuine squashfs decodes it, but
    // a vendor-obfuscated/encrypted image has valid framing (superblock + block
    // headers) over a compressed payload that will not decode. Distinguish that
    // from an ordinary corrupt/truncated image so the user knows this is not a
    // moria/binwalk limitation but a deliberately modified image.
    if (out.files == 0 && out.dirs == 0 && out.symlinks == 0) {
        bool obfuscated = c.decode_failed_valid_frame;
        auto hdr = c.r.at<uint16_t>(c.base + c.sb.inode_table_start, Endian::Little);
        if (hdr) {
            size_t size = *hdr & 0x7fff;
            bool uncompressed = (*hdr & META_UNCOMPRESSED) != 0;
            // Only judge when the pointed-at data is actually present (rules out
            // an ordinary truncated dump, where it runs past EOF).
            if (auto blk = c.r.bytes(c.base + c.sb.inode_table_start + 2,
                                     std::min<size_t>(size, METADATA_MAX))) {
                if (size == 0 || (!uncompressed && size > METADATA_MAX)) {
                    obfuscated = true;  // metadata length inconsistent with a valid superblock
                } else if (!uncompressed && !decompress(c.comp, *blk, METADATA_MAX)) {
                    obfuscated = true;  // clean framing, undecodable payload
                }
            }
        }
        if (obfuscated) {
            out.warnings.push_back(
                std::string(compressor_name(c.comp)) +
                " payload did not decode despite a valid squashfs structure - likely "
                "vendor obfuscation/encryption of the compressed data (not a moria limitation)");
            out.status = "error:undecodable-payload";
            return true;
        }
    }
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

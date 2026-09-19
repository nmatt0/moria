// ubifs.cpp — UBI + UBIFS read-only extraction. See ubifs.hpp.
//
// Two layers. UBI: each PEB carries an EC header ("UBI#", big-endian) giving the
// VID-header and data offsets, and a VID header ("UBI!") mapping the PEB to a
// (vol_id, lnum); we pick the newest (highest sqnum) PEB per logical block and
// concatenate a volume's blocks in lnum order to recover its UBIFS image. UBIFS:
// leaf nodes (common header magic 0x06101831, crc32 over [8,len)) are scanned
// directly — inode nodes give mode/size, data nodes give per-4KiB-block content
// (compr none/lzo/zlib-raw-deflate/zstd), dentry nodes give the tree. Files are
// reassembled newest-sqnum-wins; the tree is walked from root inode 1. Scanning
// leaves (not the B-tree) can surface superseded/deleted entries — acceptable
// for recovery. All reads go through the bounds-checked Reader.
#include "extract/ubifs.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "crc32.hpp"
#include "extract/decompress.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint32_t UBI_EC_MAGIC = 0x55424923;    // "UBI#"
constexpr uint32_t UBI_VID_MAGIC = 0x55424921;   // "UBI!"
constexpr uint32_t UBIFS_NODE_MAGIC = 0x06101831;
constexpr uint32_t UBIFS_ROOT_INO = 1;
constexpr uint32_t UBIFS_BLOCK_SIZE = 4096;

// UBIFS node types.
constexpr uint8_t NODE_INO = 0;
constexpr uint8_t NODE_DATA = 1;
constexpr uint8_t NODE_DENT = 2;
constexpr uint8_t NODE_SB = 6;

// UBIFS data-node compression types.
constexpr uint16_t COMPR_NONE = 0;
constexpr uint16_t COMPR_LZO = 1;
constexpr uint16_t COMPR_ZLIB = 2;   // raw DEFLATE
constexpr uint16_t COMPR_ZSTD = 3;

// Unix mode bits.
constexpr uint32_t S_IFMT = 0170000;
constexpr uint32_t S_IFDIR = 0040000;
constexpr uint32_t S_IFREG = 0100000;
constexpr uint32_t S_IFLNK = 0120000;

// Guardrails.
constexpr size_t MAX_NODES = 20000000;
constexpr size_t MAX_DEPTH = 128;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(2) << 30;
constexpr uint64_t MAX_VOLUME_BYTES = uint64_t(8) << 30;

uint64_t align8(uint64_t x) { return (x + 7) & ~uint64_t(7); }

struct DataChunk {
    uint32_t block = 0;
    uint16_t compr = 0;
    uint32_t out_size = 0;   // uncompressed length for this block
    uint64_t sqnum = 0;
    size_t data_off = 0;     // absolute offset of compressed data in the image
    uint32_t data_len = 0;   // compressed length
};

struct InodeInfo {
    uint64_t sqnum = 0;      // sqnum of the chosen (newest) inode node
    uint32_t mode = 0;
    uint64_t size = 0;
    std::vector<uint8_t> inline_data;  // symlink target etc. (from newest inode node)
    std::vector<DataChunk> data;
    bool seen = false;
};

struct Dent {
    uint64_t inum = 0;
    uint64_t sqnum = 0;
    std::string name;
};

struct Ctx {
    const Reader& r;   // over the reconstructed volume (or raw ubifs region)
    uint64_t base;
    uint64_t end;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    std::map<uint32_t, InodeInfo> inodes{};
    std::map<uint32_t, std::vector<Dent>> dents{};  // keyed by parent inode
    std::set<uint32_t> stack{};
};

std::optional<uint32_t> le32(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Little); }
std::optional<uint64_t> le64(const Reader& r, uint64_t o) { return r.at<uint64_t>(o, Endian::Little); }

// ---- UBI: reconstruct volume images from PEB headers --------------------------

// Reconstruct every UBI volume into a linear image. Returns vol_id -> image.
std::map<uint32_t, std::vector<uint8_t>> deubi(const Reader& r, uint64_t base, bool& truncated) {
    std::map<uint32_t, std::vector<uint8_t>> volumes;

    // Detect PEB size from the spacing of the first two EC headers. Every PEB
    // begins with an EC header, so scanning at the minimum block granularity the
    // second "UBI#" gives the PEB size. (Do not stop at the first non-magic step —
    // that is just the interior of the first PEB.)
    uint64_t first = 0, second = 0;
    bool have_first = false, have_second = false;
    for (uint64_t p = base; p + 4 <= r.size() && p < base + (uint64_t(16) << 20); p += 4096) {
        auto m = r.at<uint32_t>(p, Endian::Big);
        if (!m || *m != UBI_EC_MAGIC) continue;
        if (!have_first) { first = p; have_first = true; }
        else { second = p; have_second = true; break; }
    }
    if (!have_first) return volumes;
    (void)have_second;
    const uint64_t peb = second > first ? second - first : (r.size() - first);
    if (peb < 512 || peb > (uint64_t(64) << 20)) return volumes;

    // (vol_id, lnum) -> (best sqnum, data offset, leb length)
    struct Leb { uint64_t sqnum; uint64_t off; uint64_t len; };
    std::map<uint32_t, std::map<uint32_t, Leb>> map;
    uint64_t leb_len_common = 0;

    for (uint64_t p = base; p + peb <= r.size() + peb && p + 64 <= r.size(); p += peb) {
        auto ec = r.at<uint32_t>(p, Endian::Big);
        if (!ec || *ec != UBI_EC_MAGIC) continue;
        auto vid_off = r.at<uint32_t>(p + 0x10, Endian::Big);
        auto data_off = r.at<uint32_t>(p + 0x14, Endian::Big);
        if (!vid_off || !data_off || *data_off >= peb) continue;
        const uint64_t v = p + *vid_off;
        auto vm = r.at<uint32_t>(v, Endian::Big);
        if (!vm || *vm != UBI_VID_MAGIC) continue;  // free/empty PEB
        auto vol_id = r.at<uint32_t>(v + 8, Endian::Big);
        auto lnum = r.at<uint32_t>(v + 12, Endian::Big);
        auto sqnum = r.at<uint64_t>(v + 40, Endian::Big);  // ubi_vid_hdr.sqnum @40
        if (!vol_id || !lnum || !sqnum) continue;
        if (*vol_id == 0x7fffefff) continue;  // internal layout volume
        const uint64_t leb_len = peb - *data_off;
        leb_len_common = leb_len;
        auto& slot = map[*vol_id][*lnum];
        if (!(slot.len && slot.sqnum >= *sqnum)) slot = {*sqnum, p + *data_off, leb_len};
    }

    for (auto& [vol_id, lebs] : map) {
        if (lebs.empty()) continue;
        // Pack the volume's LEBs contiguously in logical (lnum ascending) order.
        // The UBIFS node scanner locates nodes by magic + CRC, so their exact
        // lnum*leb_len positions are not needed. Sizing/placing by lnum instead
        // was both wasteful and, for a *sparse* volume (few LEBs at high lnums,
        // as a large mostly-empty data volume produces), forced a clamp to the
        // source size that silently dropped every LEB past it. Sizing by the
        // actual LEB count keeps every LEB and is inherently bomb-proof: a stray
        // lnum can no longer balloon the image (its cost is one LEB, not its
        // logical offset).
        uint64_t total = uint64_t(lebs.size()) * (leb_len_common ? leb_len_common : 0);
        if (total == 0 || total > MAX_VOLUME_BYTES) { truncated = true; continue; }
        std::vector<uint8_t>& img = volumes[vol_id];
        img.reserve(total);
        for (auto& [lnum, leb] : lebs) {
            (void)lnum;
            auto span = r.bytes(leb.off, leb.len);
            if (!span) { truncated = true; continue; }
            img.insert(img.end(), span->begin(), span->end());
        }
    }
    return volumes;
}

// ---- UBIFS: scan leaf nodes, reassemble, walk tree ----------------------------

void scan_nodes(Ctx& c) {
    uint64_t pos = c.base;
    size_t nodes = 0;
    while (pos + 24 <= c.end) {
        if (nodes++ > MAX_NODES) { c.truncated = true; break; }
        auto magic = le32(c.r, pos);
        if (!magic || *magic != UBIFS_NODE_MAGIC) { pos += 8; continue; }
        auto crc = le32(c.r, pos + 4);
        auto len = le32(c.r, pos + 16);
        if (!crc || !len || *len < 24 || pos + *len > c.end) { pos += 8; continue; }
        auto body = c.r.bytes(pos + 8, *len - 8);
        if (!body || crc32_ubi(*body) != *crc) { pos += 8; continue; }

        auto sqnum = le64(c.r, pos + 8).value_or(0);
        auto ntype = c.r.bytes(pos + 20, 1);
        if (ntype) {
            uint8_t t = (*ntype)[0];
            if (t == NODE_INO) {
                auto ino = le32(c.r, pos + 24);
                auto size = le64(c.r, pos + 48);
                auto mode = le32(c.r, pos + 104);
                auto data_len = le32(c.r, pos + 112);
                if (ino && mode && size && data_len) {
                    InodeInfo& in = c.inodes[*ino];
                    if (!in.seen || sqnum >= in.sqnum) {
                        in.seen = true;
                        in.sqnum = sqnum;
                        in.mode = *mode;
                        in.size = *size;
                        in.inline_data.clear();
                        if (*data_len > 0 && *data_len < *len) {
                            auto d = c.r.bytes(pos + 160, *data_len);
                            if (d) in.inline_data.assign(d->begin(), d->end());
                        }
                    }
                }
            } else if (t == NODE_DENT) {
                auto pino = le32(c.r, pos + 24);
                auto inum = le64(c.r, pos + 40);
                auto nlen = c.r.at<uint16_t>(pos + 50, Endian::Little);
                if (pino && inum && nlen && *nlen > 0) {
                    auto name = c.r.bytes(pos + 56, *nlen);
                    if (name) {
                        std::string nm(reinterpret_cast<const char*>(name->data()), *nlen);
                        c.dents[*pino].push_back({*inum, sqnum, nm});
                    }
                }
            } else if (t == NODE_DATA) {
                auto ino = le32(c.r, pos + 24);
                auto blk = le32(c.r, pos + 28);
                auto osize = le32(c.r, pos + 40);
                auto compr = c.r.at<uint16_t>(pos + 44, Endian::Little);
                if (ino && osize && compr) {
                    InodeInfo& in = c.inodes[*ino];
                    in.data.push_back({blk.value_or(0) & 0x1FFFFFFF, *compr, *osize, sqnum,
                                       static_cast<size_t>(pos + 48), *len - 48});
                }
            }
        }
        pos = align8(pos + *len);
    }
}

std::optional<std::vector<uint8_t>> decompress_block(Ctx& c, const DataChunk& d) {
    if (d.out_size == 0 || d.out_size > UBIFS_BLOCK_SIZE) return std::nullopt;
    auto src = c.r.bytes(d.data_off, d.data_len);
    if (!src) return std::nullopt;
    if (d.compr == COMPR_NONE) {
        if (d.data_len < d.out_size) return std::nullopt;
        return std::vector<uint8_t>(src->begin(), src->begin() + d.out_size);
    }
    Compressor cc = d.compr == COMPR_LZO    ? Compressor::Lzo
                    : d.compr == COMPR_ZLIB ? Compressor::Deflate
                    : d.compr == COMPR_ZSTD ? Compressor::Zstd
                                            : Compressor::Unknown;
    if (cc == Compressor::Unknown) return std::nullopt;
    auto out = decompress(cc, *src, d.out_size);
    if (!out || out->size() != d.out_size) return std::nullopt;
    return out;
}

bool build_content(Ctx& c, const InodeInfo& in, std::vector<uint8_t>& out) {
    if (in.size > MAX_FILE_BYTES) { c.truncated = true; return false; }
    out.assign(in.size, 0);
    // Newest data node per block wins.
    std::map<uint32_t, const DataChunk*> best;
    for (const auto& d : in.data) {
        auto it = best.find(d.block);
        if (it == best.end() || d.sqnum > it->second->sqnum) best[d.block] = &d;
    }
    for (auto& [block, d] : best) {
        auto chunk = decompress_block(c, *d);
        if (!chunk) { c.truncated = true; continue; }
        uint64_t off = uint64_t(block) * UBIFS_BLOCK_SIZE;
        if (off >= in.size) continue;
        size_t n = std::min<uint64_t>(chunk->size(), in.size - off);
        std::memcpy(out.data() + off, chunk->data(), n);
    }
    return true;
}

void write_inode(Ctx& c, uint32_t ino, const std::string& rel);

void walk_dir(Ctx& c, uint32_t pino, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (c.stack.count(pino)) return;
    c.stack.insert(pino);
    auto it = c.dents.find(pino);
    if (it != c.dents.end()) {
        std::map<std::string, const Dent*> best;
        for (const auto& d : it->second) {
            auto b = best.find(d.name);
            if (b == best.end() || d.sqnum > b->second->sqnum) best[d.name] = &d;
        }
        for (auto& [name, d] : best) {
            if (name.empty() || name == "." || name == ".." ||
                name.find('/') != std::string::npos)
                continue;
            if (d->inum > 0xffffffffull) continue;
            const std::string child_rel = rel.empty() ? name : rel + "/" + name;
            uint32_t child = static_cast<uint32_t>(d->inum);
            write_inode(c, child, child_rel);
            auto ci = c.inodes.find(child);
            if (ci != c.inodes.end() && (ci->second.mode & S_IFMT) == S_IFDIR)
                walk_dir(c, child, child_rel, depth + 1);
        }
    }
    c.stack.erase(pino);
}

void write_inode(Ctx& c, uint32_t ino, const std::string& rel) {
    auto it = c.inodes.find(ino);
    if (it == c.inodes.end()) { c.truncated = true; return; }
    const InodeInfo& in = it->second;
    const uint32_t type = in.mode & S_IFMT;
    const std::string full = c.subdir + "/" + rel;
    if (type == S_IFDIR) {
        if (c.root.make_dir(full)) c.out.dirs++;
    } else if (type == S_IFLNK) {
        std::string target(in.inline_data.begin(), in.inline_data.end());
        if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
        if (!target.empty() && c.root.make_symlink(full, target)) c.out.symlinks++;
    } else if (type == S_IFREG) {
        std::vector<uint8_t> content;
        if (build_content(c, in, content)) {
            if (c.root.write_file(full, content, in.mode & 0777)) {
                c.out.files++;
                c.out.bytes += content.size();
            } else {
                c.out.warnings.push_back("write failed: " + rel);
            }
        }
    }
}

// Parse one UBIFS image (Reader over the volume) into `root/subdir`.
void parse_ubifs(const Reader& img, SafeRoot& root, const std::string& subdir, Extracted& out,
                 bool& truncated) {
    Ctx c{img, 0, img.size(), root, subdir, out};
    scan_nodes(c);
    walk_dir(c, UBIFS_ROOT_INO, "", 0);
    if (c.truncated) truncated = true;
}

}  // namespace

bool extract_ubifs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out) {
    out.offset = f.offset;
    out.type = "ubifs";
    out.root = subdir;
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    bool truncated = false;
    auto head = r.at<uint32_t>(f.offset, Endian::Big);
    if (head && *head == UBI_EC_MAGIC) {
        // UBI-wrapped: reconstruct each volume. A volume that is itself UBIFS is
        // parsed inline; any other volume (a squashfs read-only rootfs, a raw
        // ext image, ...) is written out as vol_<id>.img so the extraction
        // recursion identifies and unpacks it. This is why a squashfs-on-UBI
        // firmware now fully unpacks instead of stopping at "no ubifs volume".
        auto volumes = deubi(r, f.offset, truncated);
        int recovered = 0;
        for (auto& [vol_id, img] : volumes) {
            if (img.size() < 24) continue;
            uint32_t m;
            std::memcpy(&m, img.data(), 4);
            uint8_t ntype = img.size() > 20 ? img[20] : 0xff;
            const bool is_ubifs = (m == UBIFS_NODE_MAGIC && ntype == NODE_SB);
            if (is_ubifs) {
                Reader vr(std::span<const uint8_t>(img.data(), img.size()));
                std::string vsub =
                    volumes.size() > 1 ? subdir + "/vol_" + std::to_string(vol_id) : subdir;
                if (volumes.size() > 1) root.make_dir(vsub);
                parse_ubifs(vr, root, vsub, out, truncated);
                recovered++;
            } else {
                // Emit the raw volume image for the recursion to pick up.
                std::string rel = subdir + "/vol_" + std::to_string(vol_id) + ".img";
                if (root.write_file(rel, img, 0644)) {
                    out.files++;
                    out.bytes += img.size();
                    recovered++;
                }
            }
        }
        if (recovered == 0) {
            out.status = "error:no-ubi-volume";
            return true;
        }
    } else {
        // Raw UBIFS (no UBI layer): parse the finding region directly.
        uint64_t end = r.size();
        auto region = r.bytes(f.offset, end - f.offset);
        if (!region) {
            out.status = "error:bad-region";
            return true;
        }
        Reader vr(*region);
        parse_ubifs(vr, root, subdir, out, truncated);
    }

    out.status = truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

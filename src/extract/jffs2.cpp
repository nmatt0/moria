// jffs2.cpp — JFFS2 read-only extraction. See jffs2.hpp.
//
// Node scan: JFFS2 nodes start with a 12-byte common header (magic 0x1985,
// nodetype, totlen, hdr_crc). hdr_crc (crc32 over the first 8 bytes) gates real
// nodes from a coincidental magic, so scanning is robust to padding/erased
// (0xFF) regions. Two node types matter: INODE (0xe001, one data range of a
// file) and DIRENT (0xe002, one name in a directory). A file is reassembled by
// applying its data nodes oldest→newest version (newer overwrites overlap); the
// tree is rebuilt from dirents starting at the root inode (1). Endianness is
// detected from the magic. All disk access is range-checked through Reader.
#include "extract/jffs2.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "crc32.hpp"
#include "extract/decompress.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint16_t JFFS2_MAGIC = 0x1985;
// nodetype = FEATURE_INCOMPAT(0xc000) | NODE_ACCURATE(0x2000) | n:
//   DIRENT = ...|1 = 0xe001, INODE = ...|2 = 0xe002.
constexpr uint16_t NODETYPE_DIRENT = 0xe001;
constexpr uint16_t NODETYPE_INODE = 0xe002;

// jffs2_raw_inode compr field.
constexpr uint8_t COMPR_NONE = 0;
constexpr uint8_t COMPR_ZERO = 1;
constexpr uint8_t COMPR_RTIME = 2;
constexpr uint8_t COMPR_COPY = 4;
constexpr uint8_t COMPR_ZLIB = 6;
constexpr uint8_t COMPR_LZO = 7;

// Unix mode file-type bits (jffs2 stores a full mode).
constexpr uint32_t S_IFMT = 0170000;
constexpr uint32_t S_IFDIR = 0040000;
constexpr uint32_t S_IFREG = 0100000;
constexpr uint32_t S_IFLNK = 0120000;

constexpr uint32_t ROOT_INO = 1;

// Guardrails.
constexpr size_t MAX_NODES = 8000000;
constexpr size_t MAX_DEPTH = 128;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(1) << 30;  // 1 GiB per file

uint64_t align4(uint64_t x) { return (x + 3) & ~uint64_t(3); }

struct DataNode {
    uint32_t version = 0;
    uint32_t offset = 0;   // where in the file this data goes
    uint32_t csize = 0;    // compressed size
    uint32_t dsize = 0;    // uncompressed size
    uint8_t compr = 0;
    size_t data_off = 0;   // absolute file offset of the compressed data
};

struct InodeInfo {
    uint32_t newest = 0;   // highest inode-node version seen
    uint32_t mode = 0;
    uint32_t isize = 0;
    std::vector<DataNode> data;
};

struct Dirent {
    uint32_t version = 0;
    uint32_t ino = 0;   // 0 = unlink (name deleted)
    std::string name;
};

struct Ctx {
    const Reader& r;
    uint64_t base;
    uint64_t end;
    Endian endian = Endian::Little;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    std::map<uint32_t, InodeInfo> inodes{};
    std::map<uint32_t, std::vector<Dirent>> dirents{};  // keyed by parent inode
    std::set<uint32_t> stack{};
};

std::optional<uint16_t> r16(const Ctx& c, uint64_t off) { return c.r.at<uint16_t>(off, c.endian); }
std::optional<uint32_t> r32(const Ctx& c, uint64_t off) { return c.r.at<uint32_t>(off, c.endian); }

// RTIME decompression (jffs2's internal scheme). Bounded to destlen; a bad
// stream stops early rather than overrunning.
void rtime_decompress(const uint8_t* in, size_t srclen, std::vector<uint8_t>& out, size_t destlen) {
    out.assign(destlen, 0);
    int positions[256] = {0};
    size_t outpos = 0, pos = 0;
    while (outpos < destlen) {
        if (pos + 2 > srclen) break;
        uint8_t value = in[pos++];
        out[outpos++] = value;
        int repeat = in[pos++];
        int backoffs = positions[value];
        positions[value] = static_cast<int>(outpos);
        while (repeat-- > 0) {
            if (outpos >= destlen || backoffs < 0 || static_cast<size_t>(backoffs) >= outpos) break;
            out[outpos++] = out[backoffs++];
        }
    }
    out.resize(outpos);
}

// Decompress one data node into `out` (exactly dsize bytes on success).
bool decompress_node(Ctx& c, const DataNode& n, std::vector<uint8_t>& out) {
    if (n.dsize == 0) { out.clear(); return true; }
    if (n.dsize > MAX_FILE_BYTES) return false;
    if (n.compr == COMPR_ZERO) { out.assign(n.dsize, 0); return true; }

    auto src = c.r.bytes(n.data_off, n.csize);
    if (!src) return false;

    if (n.compr == COMPR_NONE || n.compr == COMPR_COPY) {
        if (n.csize < n.dsize) return false;
        out.assign(src->begin(), src->begin() + n.dsize);
        return true;
    }
    if (n.compr == COMPR_RTIME) {
        rtime_decompress(src->data(), n.csize, out, n.dsize);
        return out.size() == n.dsize;
    }
    if (n.compr == COMPR_ZLIB || n.compr == COMPR_LZO) {
        Compressor cc = (n.compr == COMPR_ZLIB) ? Compressor::Gzip : Compressor::Lzo;
        auto d = decompress(cc, *src, n.dsize);
        if (!d || d->size() != n.dsize) return false;
        out = std::move(*d);
        return true;
    }
    return false;  // RUBINMIPS / DYNRUBIN etc: unsupported
}

// Reassemble an inode's byte content (regular file data or symlink target).
bool build_content(Ctx& c, const InodeInfo& info, std::vector<uint8_t>& out) {
    if (info.isize > MAX_FILE_BYTES) { c.truncated = true; return false; }
    out.assign(info.isize, 0);
    // Apply data nodes oldest -> newest so the newest version wins on overlap.
    std::vector<const DataNode*> nodes;
    nodes.reserve(info.data.size());
    for (const auto& d : info.data) nodes.push_back(&d);
    std::sort(nodes.begin(), nodes.end(),
              [](const DataNode* a, const DataNode* b) { return a->version < b->version; });
    for (const DataNode* d : nodes) {
        std::vector<uint8_t> chunk;
        if (!decompress_node(c, *d, chunk)) { c.truncated = true; continue; }
        if (chunk.empty()) continue;
        if (d->offset >= info.isize) continue;
        size_t n = std::min<size_t>(chunk.size(), info.isize - d->offset);
        std::memcpy(out.data() + d->offset, chunk.data(), n);
    }
    return true;
}

void scan_nodes(Ctx& c) {
    uint64_t pos = c.base;
    size_t nodes = 0;
    while (pos + 12 <= c.end) {
        if (nodes++ > MAX_NODES) { c.truncated = true; break; }
        auto magic = r16(c, pos);
        if (!magic || *magic != JFFS2_MAGIC) { pos = align4(pos + 4); continue; }
        auto nodetype = r16(c, pos + 2);
        auto totlen = r32(c, pos + 4);
        auto hdr_crc = r32(c, pos + 8);
        if (!nodetype || !totlen || !hdr_crc) { pos = align4(pos + 4); continue; }
        // hdr_crc covers the first 8 bytes; confirms a real node.
        auto hdr = c.r.bytes(pos, 8);
        if (!hdr || crc32_jffs2(*hdr) != *hdr_crc) { pos = align4(pos + 4); continue; }
        if (*totlen < 12 || pos + *totlen > c.end) { pos = align4(pos + 4); continue; }

        if (*nodetype == NODETYPE_INODE && *totlen >= 68) {
            auto ino = r32(c, pos + 12);
            auto version = r32(c, pos + 16);
            auto mode = r32(c, pos + 20);
            auto isize = r32(c, pos + 28);
            auto doff = r32(c, pos + 44);
            auto csize = r32(c, pos + 48);
            auto dsize = r32(c, pos + 52);
            auto compr = c.r.bytes(pos + 56, 1);
            if (ino && version && mode && isize && doff && csize && dsize && compr) {
                InodeInfo& in = c.inodes[*ino];
                if (*version >= in.newest) {
                    in.newest = *version;
                    in.mode = *mode;
                    in.isize = *isize;
                }
                if (*dsize && pos + 68 + *csize <= pos + *totlen) {
                    in.data.push_back({*version, *doff, *csize, *dsize, (*compr)[0],
                                       static_cast<size_t>(pos + 68)});
                }
            }
        } else if (*nodetype == NODETYPE_DIRENT && *totlen >= 40) {
            auto pino = r32(c, pos + 12);
            auto version = r32(c, pos + 16);
            auto ino = r32(c, pos + 20);
            auto nsize = c.r.bytes(pos + 28, 1);
            if (pino && version && nsize) {
                uint8_t nl = (*nsize)[0];
                auto name = c.r.bytes(pos + 40, nl);
                if (name && nl > 0) {
                    std::string nm(reinterpret_cast<const char*>(name->data()), nl);
                    c.dirents[*pino].push_back({*version, ino ? *ino : 0, nm});
                }
            }
        }
        pos = align4(pos + *totlen);
    }
}

void write_inode(Ctx& c, uint32_t ino, const std::string& rel);

void walk_dir(Ctx& c, uint32_t pino, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (c.stack.count(pino)) return;
    c.stack.insert(pino);

    auto it = c.dirents.find(pino);
    if (it != c.dirents.end()) {
        // Resolve each name to its highest-version dirent (newest wins; ino==0 = deleted).
        std::map<std::string, const Dirent*> best;
        for (const auto& d : it->second) {
            auto b = best.find(d.name);
            if (b == best.end() || d.version > b->second->version) best[d.name] = &d;
        }
        for (auto& [name, d] : best) {
            if (d->ino == 0) continue;  // deleted
            if (name == "." || name == ".." || name.find('/') != std::string::npos) continue;
            const std::string child_rel = rel.empty() ? name : rel + "/" + name;
            write_inode(c, d->ino, child_rel);
            auto ci = c.inodes.find(d->ino);
            if (ci != c.inodes.end() && (ci->second.mode & S_IFMT) == S_IFDIR)
                walk_dir(c, d->ino, child_rel, depth + 1);
        }
    }
    c.stack.erase(pino);
}

// Create the filesystem object for inode `ino` at `rel` (relative to subdir).
void write_inode(Ctx& c, uint32_t ino, const std::string& rel) {
    auto it = c.inodes.find(ino);
    if (it == c.inodes.end()) { c.truncated = true; return; }
    const InodeInfo& info = it->second;
    const uint32_t type = info.mode & S_IFMT;
    const std::string full = c.subdir + "/" + rel;

    if (type == S_IFDIR) {
        if (c.root.make_dir(full)) c.out.dirs++;
    } else if (type == S_IFLNK) {
        std::vector<uint8_t> content;
        if (build_content(c, info, content)) {
            std::string target(content.begin(), content.end());
            if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
            if (!target.empty() && c.root.make_symlink(full, target)) c.out.symlinks++;
        }
    } else if (type == S_IFREG) {
        std::vector<uint8_t> content;
        if (build_content(c, info, content)) {
            if (c.root.write_file(full, content, info.mode & 0777)) {
                c.out.files++;
                c.out.bytes += content.size();
            } else {
                c.out.warnings.push_back("write failed: " + rel);
            }
        }
    }
    // Other types: skipped.
}

}  // namespace

bool extract_jffs2(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out) {
    out.offset = f.offset;
    out.type = "jffs2";
    out.root = subdir;

    // Scan the whole image from the finding offset, not just the finding's size:
    // a jffs2 filesystem is often reported as several findings (coalescing breaks
    // where embedded file data — e.g. boot-logo PNGs — is independently detected),
    // and its nodes run across the entire region. hdr_crc gates real nodes, so
    // scanning past the FS into unrelated data is safe (non-nodes are skipped).
    Ctx c{r, f.offset, r.size(), Endian::Little, root, subdir, out};

    // Detect endianness from the first node's magic.
    auto le = r.at<uint16_t>(f.offset, Endian::Little);
    auto be = r.at<uint16_t>(f.offset, Endian::Big);
    if (le && *le == JFFS2_MAGIC) c.endian = Endian::Little;
    else if (be && *be == JFFS2_MAGIC) c.endian = Endian::Big;
    // else default LE; scan_nodes will find nothing and report an empty result.

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    scan_nodes(c);
    if (c.inodes.empty() && c.dirents.empty()) {
        out.status = "error:no-nodes";
        return true;
    }
    walk_dir(c, ROOT_INO, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

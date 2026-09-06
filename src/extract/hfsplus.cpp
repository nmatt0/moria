// hfsplus.cpp — HFS+/HFSX extraction. See hfsplus.hpp.
//
// All multi-byte fields are big-endian. Layout:
//  - Volume Header @ base+1024: signature 'H+'(0x482B)/'HX'(0x4858), blockSize @40,
//    totalBlocks @44, and the special-file forks (catalogFile @272). A fork is a
//    HFSPlusForkData: logicalSize(u64), clumpSize(u32), totalBlocks(u32), then 8
//    extents {startBlock(u32), blockCount(u32)}.
//  - Catalog File: a B-tree. Node 0 is the header node; its BTHeaderRec gives the
//    node size and the first leaf node. Leaf nodes form a forward-linked chain
//    (BTNodeDescriptor.fLink), so every catalog record is reachable by walking the
//    chain — no index traversal needed. Each leaf record is a HFSPlusCatalogKey
//    {keyLength(u16), parentID(u32), nodeName: length(u16) + BE UTF-16} followed by
//    a folder(1)/file(2)/thread(3,4) record.
//  - A file record's data fork (@88 in the record) has the file's extents; a folder
//    record's folderID(@8) is its CNID. The tree is rebuilt from the root folder
//    (CNID 2) by grouping records on their parent CNID.
#include "extract/hfsplus.hpp"

#include "byteorder.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint16_t SIG_HFSPLUS = 0x482B;  // 'H+'
constexpr uint16_t SIG_HFSX = 0x4858;     // 'HX'
constexpr uint32_t ROOT_CNID = 2;

constexpr uint16_t REC_FOLDER = 1;
constexpr uint16_t REC_FILE = 2;

constexpr uint16_t S_IFMT_ = 0170000;
constexpr uint16_t S_IFLNK_ = 0120000;
constexpr uint16_t S_IFDIR_ = 0040000;

constexpr size_t MAX_CATALOG_BYTES = size_t(512) << 20;  // 512 MiB catalog cap
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;
constexpr size_t MAX_RECORDS = 4000000;
constexpr size_t MAX_DEPTH = 128;

std::optional<uint16_t> u16(const Reader& r, uint64_t o) { return r.at<uint16_t>(o, Endian::Big); }
std::optional<uint32_t> u32(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Big); }
std::optional<uint64_t> u64(const Reader& r, uint64_t o) { return r.at<uint64_t>(o, Endian::Big); }

#include "extract/hfsplus_nfc.inc"

// Canonical composition of a (starter, combining-mark) pair, or 0 if none.
uint32_t nfc_compose(uint32_t base, uint32_t mark) {
    if (base > 0xFFFF || mark < 0x300 || mark > 0x36F) return 0;
    const uint32_t key = (base << 16) | mark;
    size_t lo = 0, hi = sizeof(kNfcCompose) / sizeof(kNfcCompose[0]);
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (kNfcCompose[mid][0] < key) lo = mid + 1;
        else hi = mid;
    }
    return (lo < sizeof(kNfcCompose) / sizeof(kNfcCompose[0]) && kNfcCompose[lo][0] == key)
               ? kNfcCompose[lo][1]
               : 0;
}

// Big-endian UTF-16 -> UTF-8. HFS+ stores names decomposed (NFD); fold them back
// to NFC (matching every other HFS+ reader) by composing each starter with the
// combining marks that follow it.
std::string utf16be_to_utf8(const std::vector<uint16_t>& u) {
    // 1. Decode UTF-16 code units to code points (with surrogate pairing).
    std::vector<uint32_t> cps;
    cps.reserve(u.size());
    for (size_t i = 0; i < u.size(); ++i) {
        uint32_t cp = u[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < u.size() && u[i + 1] >= 0xDC00 &&
            u[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (u[++i] - 0xDC00);
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
        cps.push_back(cp);
    }
    // 2. Compose: fold combining marks into the preceding starter, greedily.
    std::vector<uint32_t> out;
    out.reserve(cps.size());
    for (uint32_t cp : cps) {
        if (!out.empty()) {
            if (uint32_t comp = nfc_compose(out.back(), cp)) {
                out.back() = comp;
                continue;
            }
        }
        out.push_back(cp);
    }
    // 3. Encode to UTF-8.
    std::string s;
    for (uint32_t cp : out) {
        if (cp < 0x80) {
            s += static_cast<char>(cp);
        } else if (cp < 0x800) {
            s += static_cast<char>(0xC0 | (cp >> 6));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            s += static_cast<char>(0xE0 | (cp >> 12));
            s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            s += static_cast<char>(0xF0 | (cp >> 18));
            s += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    return s;
}

struct Extent {
    uint32_t start = 0;
    uint32_t count = 0;
};

// A folder or file catalog record, keyed for tree reconstruction by parent CNID.
struct Node {
    std::string name;
    uint32_t parent = 0;
    uint32_t cnid = 0;
    bool is_dir = false;
    uint16_t mode = 0;             // file: permissions.fileMode (for symlink detect)
    uint64_t data_size = 0;        // file: data-fork logical size
    Extent extents[8]{};           // file: data-fork inline extents
};

struct Ctx {
    const Reader& r;
    uint64_t base;
    uint32_t block_size;
    uint64_t vol_blocks;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    std::vector<uint8_t> catalog;                    // the whole catalog fork
    std::map<uint32_t, std::vector<size_t>> by_parent;  // parent CNID -> node indices
    std::vector<Node> nodes;
    std::set<uint32_t> visited;
    bool truncated = false;
};

// Read a fork's extents (in `blob`) into a contiguous byte buffer up to `want`.
bool read_extents(Ctx& c, const Extent* ext, int n, uint64_t want, std::vector<uint8_t>& out) {
    out.clear();
    if (want > MAX_FILE_BYTES) { c.truncated = true; want = MAX_FILE_BYTES; }
    out.reserve(static_cast<size_t>(std::min<uint64_t>(want, MAX_CATALOG_BYTES)));
    for (int i = 0; i < n && out.size() < want; ++i) {
        if (ext[i].count == 0) continue;
        // guard against absurd extents pointing outside the volume
        if (uint64_t(ext[i].start) + ext[i].count > c.vol_blocks && c.vol_blocks) {
            c.truncated = true;
            break;
        }
        uint64_t off = c.base + uint64_t(ext[i].start) * c.block_size;
        uint64_t len = uint64_t(ext[i].count) * c.block_size;
        uint64_t take = std::min<uint64_t>(len, want - out.size());
        auto d = c.r.bytes(static_cast<size_t>(off), static_cast<size_t>(take));
        if (!d) { c.truncated = true; break; }
        out.insert(out.end(), d->begin(), d->end());
    }
    if (out.size() < want) c.truncated = true;
    return !out.empty() || want == 0;
}

// Read the 8 inline extents of a HFSPlusForkData at absolute offset `o`.
void read_fork_extents(const Reader& r, uint64_t o, Extent* ext) {
    for (int i = 0; i < 8; ++i) {
        auto s = u32(r, o + 16 + i * 8);
        auto n = u32(r, o + 16 + i * 8 + 4);
        ext[i].start = s ? *s : 0;
        ext[i].count = n ? *n : 0;
    }
}

// Parse one catalog leaf record (key + folder/file body) at byte `rp` in the
// catalog, of length `rlen`. Appends a Node for folder/file records.
void parse_record(Ctx& c, size_t rp, size_t rlen) {
    const std::vector<uint8_t>& cat = c.catalog;
    if (rp + 8 > cat.size() || rlen < 8) return;
    auto be16 = [&](size_t p) -> uint32_t { return load_be16(cat, p); };
    auto be32 = [&](size_t p) -> uint32_t { return load_be32(cat, p); };
    const uint32_t key_len = be16(rp);
    const size_t data_off = rp + 2 + key_len;
    if (key_len < 6 || data_off + 2 > rp + rlen || data_off + 2 > cat.size()) return;
    const uint32_t parent = be32(rp + 2);
    const uint32_t name_len = be16(rp + 6);
    if (name_len > 255 || rp + 8 + uint64_t(name_len) * 2 > cat.size()) return;
    std::vector<uint16_t> name16(name_len);
    for (uint32_t i = 0; i < name_len; ++i) name16[i] = be16(rp + 8 + i * 2);
    std::string name = utf16be_to_utf8(name16);

    const uint32_t rec_type = be16(data_off);
    if (rec_type == REC_FOLDER) {
        if (data_off + 12 > cat.size()) return;
        Node n;
        n.name = std::move(name);
        n.parent = parent;
        n.cnid = be32(data_off + 8);  // folderID
        n.is_dir = true;
        c.by_parent[parent].push_back(c.nodes.size());
        c.nodes.push_back(std::move(n));
    } else if (rec_type == REC_FILE) {
        // HFSPlusCatalogFile: fileID@8, permissions.fileMode@42, dataFork@88.
        if (data_off + 88 + 80 > cat.size()) return;
        Node n;
        n.name = std::move(name);
        n.parent = parent;
        n.cnid = be32(data_off + 8);
        n.is_dir = false;
        n.mode = static_cast<uint16_t>(be16(data_off + 42));
        n.data_size = (uint64_t(be32(data_off + 88)) << 32) | be32(data_off + 92);
        const size_t fork = data_off + 88;
        for (int i = 0; i < 8; ++i) {
            n.extents[i].start = be32(fork + 16 + i * 8);
            n.extents[i].count = be32(fork + 16 + i * 8 + 4);
        }
        c.by_parent[parent].push_back(c.nodes.size());
        c.nodes.push_back(std::move(n));
    }
    // rec_type 3/4 (threads) are ignored: the parent CNID in every folder/file key
    // is enough to rebuild the tree.
}

// Walk the catalog B-tree leaf chain, parsing every folder/file record.
void collect_records(Ctx& c, uint32_t node_size, uint32_t first_leaf) {
    const std::vector<uint8_t>& cat = c.catalog;
    if (node_size < 512 || (node_size & (node_size - 1)) != 0) return;
    const uint32_t total_nodes = static_cast<uint32_t>(cat.size() / node_size);
    std::set<uint32_t> seen;
    uint32_t node = first_leaf;
    while (node != 0 && node < total_nodes && c.nodes.size() < MAX_RECORDS) {
        if (!seen.insert(node).second) break;  // cycle guard
        const size_t nbase = size_t(node) * node_size;
        // BTNodeDescriptor: fLink@0, bLink@4, kind@8(s8), height@9, numRecords@10.
        const uint32_t flink = (uint32_t(cat[nbase]) << 24) | (uint32_t(cat[nbase + 1]) << 16) |
                               (uint32_t(cat[nbase + 2]) << 8) | cat[nbase + 3];
        const int8_t kind = static_cast<int8_t>(cat[nbase + 8]);
        const uint16_t num = static_cast<uint16_t>((uint32_t(cat[nbase + 10]) << 8) | cat[nbase + 11]);
        if (kind == -1) {  // kBTLeafNode
            for (uint16_t i = 0; i < num; ++i) {
                // record offsets are u16 from the node end, growing backward.
                const size_t off_pos = nbase + node_size - 2 * (i + 1);
                const size_t nxt_pos = nbase + node_size - 2 * (i + 2);
                if (off_pos + 2 > cat.size() || nxt_pos + 2 > cat.size()) break;
                const uint16_t roff = static_cast<uint16_t>((uint32_t(cat[off_pos]) << 8) | cat[off_pos + 1]);
                const uint16_t rnext = static_cast<uint16_t>((uint32_t(cat[nxt_pos]) << 8) | cat[nxt_pos + 1]);
                if (roff < 14 || roff >= node_size || rnext <= roff) continue;
                parse_record(c, nbase + roff, rnext - roff);
            }
        }
        node = flink;
    }
}

void walk(Ctx& c, uint32_t cnid, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (!c.visited.insert(cnid).second) return;  // cycle guard on CNID
    auto it = c.by_parent.find(cnid);
    if (it == c.by_parent.end()) return;
    for (size_t idx : it->second) {
        const Node& n = c.nodes[idx];
        if (n.name.empty() || n.name == "." || n.name == "..") continue;
        if (n.name.find('/') != std::string::npos) continue;  // never split a name
        const std::string child = rel.empty() ? n.name : rel + "/" + n.name;
        const std::string full = c.subdir + "/" + child;
        if (n.is_dir) {
            if (c.root.make_dir(full)) c.out.dirs++;
            walk(c, n.cnid, child, depth + 1);
        } else if ((n.mode & S_IFMT_) == S_IFLNK_) {
            std::vector<uint8_t> data;
            read_extents(c, n.extents, 8, n.data_size, data);
            std::string target(data.begin(), data.end());
            if (!target.empty() && target.find('\0') == std::string::npos &&
                c.root.make_symlink(full, target))
                c.out.symlinks++;
        } else {
            std::vector<uint8_t> data;
            read_extents(c, n.extents, 8, n.data_size, data);
            const uint32_t mode = (n.mode & 0777) ? (n.mode & 0777) : 0644;
            if (c.root.write_file(full, data, mode)) {
                c.out.files++;
                c.out.bytes += data.size();
            }
        }
    }
}

}  // namespace

bool extract_hfsplus(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                     Extracted& out) {
    out.offset = f.offset;
    out.type = "hfsplus";
    out.root = subdir;

    const uint64_t vh = f.offset + 1024;
    auto sig = u16(r, vh);
    auto bs = u32(r, vh + 40);
    auto tblocks = u32(r, vh + 44);
    if (!sig || (*sig != SIG_HFSPLUS && *sig != SIG_HFSX) || !bs || !tblocks) {
        out.status = "error:bad-volume-header";
        return true;
    }
    const uint32_t block_size = *bs;
    if (block_size < 512 || block_size > 65536 || (block_size & (block_size - 1)) != 0) {
        out.status = "error:bad-volume-header";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    Ctx c{r, f.offset, block_size, *tblocks, root, subdir, out, {}, {}, {}, {}, false};

    // Catalog File fork lives at volume-header offset 272.
    const uint64_t cat_fork = vh + 272;
    auto cat_logical = u64(r, cat_fork);
    if (!cat_logical || *cat_logical == 0) { out.status = "error:no-catalog"; return true; }
    Extent cat_ext[8];
    read_fork_extents(r, cat_fork, cat_ext);
    uint64_t want = std::min<uint64_t>(*cat_logical, MAX_CATALOG_BYTES);
    if (!read_extents(c, cat_ext, 8, want, c.catalog) || c.catalog.size() < 32 + 14) {
        out.status = "error:catalog-read";
        return true;
    }

    // B-tree header node (node 0): BTHeaderRec @14 gives nodeSize@18, firstLeaf@10.
    auto be16c = [&](size_t p) -> uint32_t {
        return (uint32_t(c.catalog[p]) << 8) | c.catalog[p + 1];
    };
    auto be32c = [&](size_t p) -> uint32_t {
        return (uint32_t(c.catalog[p]) << 24) | (uint32_t(c.catalog[p + 1]) << 16) |
               (uint32_t(c.catalog[p + 2]) << 8) | c.catalog[p + 3];
    };
    const uint32_t first_leaf = be32c(14 + 10);
    const uint32_t node_size = be16c(14 + 18);

    collect_records(c, node_size, first_leaf);
    walk(c, ROOT_CNID, "", 0);

    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

// cramfs.cpp — cramfs extraction. See cramfs.hpp.
//
// Superblock: magic 0x28cd3d45 @0, "Compressed ROMFS" @16; the 12-byte root
// inode sits at offset 64. Inode (little-endian bit fields):
//   u32 @0: mode:16, uid:16;   u32 @4: size:24, gid:8;   u32 @8: namelen:6, offset:26.
// The name (namelen*4 bytes, NUL-padded) follows the 12-byte inode. `offset*4`
// (from the filesystem base) points at the inode's data: for a directory, a run
// of child inodes spanning `size` bytes; for a file/symlink, ceil(size/4096)
// u32 block-END offsets followed by zlib blocks. All reads are range-checked.
#include "extract/cramfs.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "extract/decompress.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint32_t CRAMFS_MAGIC = 0x28cd3d45;
constexpr size_t ROOT_INODE = 64;
constexpr size_t BLOCK = 4096;

constexpr uint32_t S_IFMT = 0170000;
constexpr uint32_t S_IFDIR = 0040000;
constexpr uint32_t S_IFREG = 0100000;
constexpr uint32_t S_IFLNK = 0120000;

constexpr size_t MAX_ENTRIES = 4000000;
constexpr size_t MAX_DEPTH = 128;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(64) << 20;  // cramfs size field is 24-bit (<=16 MiB)

struct Inode {
    uint32_t mode = 0;
    uint32_t size = 0;
    uint32_t namelen = 0;   // in 4-byte units
    uint32_t data_off = 0;  // absolute offset of the inode's data
    std::string name;
};

struct Ctx {
    const Reader& r;
    uint64_t base;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t entries = 0;
    std::set<uint64_t> visited{};
};

// Parse the 12-byte inode at absolute offset `at` (name read too).
std::optional<Inode> read_inode(Ctx& c, uint64_t at) {
    auto w0 = c.r.at<uint32_t>(at, Endian::Little);
    auto w1 = c.r.at<uint32_t>(at + 4, Endian::Little);
    auto w2 = c.r.at<uint32_t>(at + 8, Endian::Little);
    if (!w0 || !w1 || !w2) return std::nullopt;
    Inode n;
    n.mode = *w0 & 0xffff;
    n.size = *w1 & 0xffffff;
    n.namelen = *w2 & 0x3f;
    n.data_off = c.base + ((*w2 >> 6) * 4);
    if (n.namelen) {
        auto nm = c.r.bytes(at + 12, n.namelen * 4);
        if (nm) {
            n.name.assign(reinterpret_cast<const char*>(nm->data()), n.namelen * 4);
            if (auto z = n.name.find('\0'); z != std::string::npos) n.name.resize(z);
        }
    }
    return n;
}

// Read + decompress a file/symlink's block-compressed content into `out`.
bool read_content(Ctx& c, const Inode& n, std::vector<uint8_t>& out) {
    if (n.size == 0) { out.clear(); return true; }
    if (n.size > MAX_FILE_BYTES) { c.truncated = true; return false; }
    const uint32_t nblocks = (n.size + BLOCK - 1) / BLOCK;
    out.reserve(n.size);
    uint64_t block_start = n.data_off + uint64_t(nblocks) * 4;  // after the pointer array
    for (uint32_t i = 0; i < nblocks; ++i) {
        auto endp = c.r.at<uint32_t>(n.data_off + uint64_t(i) * 4, Endian::Little);
        if (!endp) { c.truncated = true; return false; }
        uint64_t block_end = c.base + (*endp & 0x3fffffff);  // mask any high flag bits
        if (block_end < block_start || block_end - block_start > BLOCK + 64) {
            c.truncated = true;
            return false;
        }
        auto comp = c.r.bytes(block_start, static_cast<size_t>(block_end - block_start));
        if (!comp) { c.truncated = true; return false; }
        const size_t want = std::min<size_t>(BLOCK, n.size - out.size());
        auto dec = decompress(Compressor::Gzip, *comp, want);
        if (!dec) { c.truncated = true; return false; }
        out.insert(out.end(), dec->begin(), dec->end());
        block_start = block_end;
    }
    out.resize(n.size);
    return true;
}

void walk_dir(Ctx& c, const Inode& dir, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    if (dir.data_off == c.base || dir.size == 0) return;  // empty dir
    if (!c.visited.insert(dir.data_off).second) return;   // cycle guard

    uint64_t pos = dir.data_off;
    const uint64_t end = dir.data_off + dir.size;
    while (pos + 12 <= end) {
        if (c.entries++ > MAX_ENTRIES) { c.truncated = true; return; }
        auto ni = read_inode(c, pos);
        if (!ni) { c.truncated = true; return; }
        const Inode& n = *ni;
        const uint64_t next = pos + 12 + uint64_t(n.namelen) * 4;
        if (next <= pos || next > end) break;

        const uint32_t type = n.mode & S_IFMT;
        const bool named =
            !n.name.empty() && n.name != "." && n.name != ".." &&
            n.name.find('/') == std::string::npos && n.name.find('\0') == std::string::npos;
        if (named) {
            const std::string child_rel = rel.empty() ? n.name : rel + "/" + n.name;
            const std::string full = c.subdir + "/" + child_rel;
            if (type == S_IFDIR) {
                if (c.root.make_dir(full)) c.out.dirs++;
                walk_dir(c, n, child_rel, depth + 1);
            } else if (type == S_IFLNK) {
                std::vector<uint8_t> t;
                if (read_content(c, n, t)) {
                    std::string target(t.begin(), t.end());
                    if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
                    if (!target.empty() && c.root.make_symlink(full, target)) c.out.symlinks++;
                }
            } else if (type == S_IFREG) {
                std::vector<uint8_t> data;
                if (read_content(c, n, data)) {
                    if (c.root.write_file(full, data, n.mode & 0777)) {
                        c.out.files++;
                        c.out.bytes += data.size();
                    } else {
                        c.out.warnings.push_back("write failed: " + child_rel);
                    }
                }
            }
        }
        pos = next;
    }
}

}  // namespace

bool extract_cramfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out) {
    out.offset = f.offset;
    out.type = "cramfs";
    out.root = subdir;

    auto magic = r.at<uint32_t>(f.offset, Endian::Little);
    if (!magic || *magic != CRAMFS_MAGIC) {
        out.status = "error:bad-magic";  // big-endian cramfs not handled
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    Ctx c{r, f.offset, root, subdir, out};
    auto rootin = read_inode(c, f.offset + ROOT_INODE);
    if (!rootin || (rootin->mode & S_IFMT) != S_IFDIR) {
        out.status = "error:bad-root";
        return true;
    }
    walk_dir(c, *rootin, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

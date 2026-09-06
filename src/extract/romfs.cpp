// romfs.cpp — Linux romfs extraction. See romfs.hpp.
//
// Format (all big-endian): superblock magic "-rom1fs-" @0, full_size @8,
// checksum @12, then a NUL-terminated volume name padded to 16 bytes. The first
// file header follows. Each file header: next_filehdr @0 (offset&~0xF of the
// next header in this directory; low 3 bits = type, bit 3 = exec), spec_info @4
// (dir: first child header; symlink/regular: 0; hardlink: target header), size
// @8, checksum @12, then a NUL-terminated name padded to 16, then the data. The
// header offsets are absolute from the filesystem start; a visited-set guards
// against cycles. All reads are range-checked through Reader.
#include "extract/romfs.hpp"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

// romfs file types (next_filehdr & 7).
constexpr uint32_t TYPE_HARDLINK = 0;
constexpr uint32_t TYPE_DIR = 1;
constexpr uint32_t TYPE_REG = 2;
constexpr uint32_t TYPE_SYMLINK = 3;

constexpr size_t MAX_ENTRIES = 2000000;
constexpr size_t MAX_DEPTH = 128;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;

uint64_t align16(uint64_t x) { return (x + 15) & ~uint64_t(15); }

struct Ctx {
    const Reader& r;
    uint64_t base;
    uint64_t end;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t entries = 0;
    std::set<uint64_t> visited{};
};

// Read a NUL-terminated name at absolute offset `off` (cap 512).
std::string read_name(const Reader& r, uint64_t off) {
    std::string s;
    for (size_t i = 0; i < 512; ++i) {
        auto b = r.bytes(off + i, 1);
        if (!b || (*b)[0] == 0) break;
        s += static_cast<char>((*b)[0]);
    }
    return s;
}

// Walk one directory's header chain (absolute offsets), writing entries under rel.
void walk_chain(Ctx& c, uint64_t hdr, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    while (hdr != 0 && hdr + 16 <= c.end) {
        if (c.entries++ > MAX_ENTRIES) { c.truncated = true; return; }
        if (!c.visited.insert(hdr).second) return;  // cycle guard

        auto next = c.r.at<uint32_t>(hdr + 0, Endian::Big);
        auto spec = c.r.at<uint32_t>(hdr + 4, Endian::Big);
        auto size = c.r.at<uint32_t>(hdr + 8, Endian::Big);
        if (!next || !spec || !size) { c.truncated = true; return; }

        const uint32_t type = *next & 7;
        const uint64_t next_off = c.base + (*next & ~uint32_t(0xF));
        const std::string name = read_name(c.r, hdr + 16);
        const uint64_t data_off = align16(hdr + 16 + name.size() + 1);

        const bool special = name.empty() || name == "." || name == "..";
        if (!special && name.find('/') == std::string::npos) {
            const std::string child_rel = rel.empty() ? name : rel + "/" + name;
            const std::string full = c.subdir + "/" + child_rel;
            if (type == TYPE_DIR) {
                if (c.root.make_dir(full)) c.out.dirs++;
                walk_chain(c, c.base + *spec, child_rel, depth + 1);
            } else if (type == TYPE_REG) {
                if (*size <= MAX_FILE_BYTES) {
                    auto d = c.r.bytes(data_off, *size);
                    if (d) {
                        std::vector<uint8_t> data(d->begin(), d->end());
                        if (c.root.write_file(full, data, 0644)) {
                            c.out.files++;
                            c.out.bytes += data.size();
                        } else {
                            c.out.warnings.push_back("write failed: " + child_rel);
                        }
                    } else {
                        c.truncated = true;
                    }
                }
            } else if (type == TYPE_SYMLINK) {
                auto d = c.r.bytes(data_off, *size);
                if (d) {
                    std::string target(d->begin(), d->end());
                    if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
                    if (!target.empty() && c.root.make_symlink(full, target)) c.out.symlinks++;
                }
            }
            // hardlink / device / fifo / socket: skipped.
            (void)TYPE_HARDLINK;
        }

        hdr = (next_off > c.base) ? next_off : 0;  // next in this directory (0 = end)
    }
}

}  // namespace

bool extract_romfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out) {
    out.offset = f.offset;
    out.type = "romfs";
    out.root = subdir;

    auto magic = r.bytes(f.offset, 8);
    if (!magic || std::string(reinterpret_cast<const char*>(magic->data()), 8) != "-rom1fs-") {
        out.status = "error:bad-magic";
        return true;
    }
    auto full_size = r.at<uint32_t>(f.offset + 8, Endian::Big);
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    Ctx c{r, f.offset, r.size(), root, subdir, out};
    if (full_size && f.offset + *full_size <= r.size()) c.end = f.offset + *full_size;

    // The first file header follows the NUL-terminated volume name (padded to 16).
    const std::string volname = read_name(r, f.offset + 16);
    const uint64_t first = align16(f.offset + 16 + volname.size() + 1);
    walk_chain(c, first, "", 0);

    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

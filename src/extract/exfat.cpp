// exfat.cpp — exFAT extraction. See exfat.hpp.
#include "extract/exfat.hpp"

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

constexpr uint8_t ENTRY_FILE = 0x85;
constexpr uint8_t ENTRY_STREAM = 0xC0;
constexpr uint8_t ENTRY_NAME = 0xC1;

constexpr uint16_t ATTR_DIR = 0x10;
constexpr uint8_t STREAM_NOFATCHAIN = 0x02;  // flags bit1

constexpr size_t MAX_DEPTH = 128;
constexpr size_t MAX_ENTRIES = 4000000;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;
constexpr uint64_t MAX_DIR_BYTES = uint64_t(256) << 20;

std::optional<uint32_t> u32(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Little); }

struct Fs {
    const Reader& r;
    uint64_t base;
    uint64_t fat_off;       // absolute byte offset of the FAT
    uint64_t heap_off;      // absolute byte offset of cluster 2
    uint32_t cluster_count;
    uint64_t cluster_bytes;
};

uint64_t cluster_offset(const Fs& fs, uint32_t c) {
    return fs.heap_off + uint64_t(c - 2) * fs.cluster_bytes;
}

uint32_t fat_next(const Fs& fs, uint32_t c) {
    auto v = u32(fs.r, fs.fat_off + uint64_t(c) * 4);
    if (!v) return 0xFFFFFFFF;
    return *v;
}

// Read a cluster run into `out`, up to `cap` bytes. Contiguous when `nofatchain`,
// else following the FAT. A visited guard bounds runaway chains.
bool read_run(const Fs& fs, uint32_t first, bool nofatchain, uint64_t cap,
              std::vector<uint8_t>& out) {
    out.clear();
    uint32_t c = first;
    std::set<uint32_t> seen;
    while (c >= 2 && c < fs.cluster_count + 2 && out.size() < cap) {
        auto d = fs.r.bytes(static_cast<size_t>(cluster_offset(fs, c)),
                            static_cast<size_t>(fs.cluster_bytes));
        if (!d) return false;
        out.insert(out.end(), d->begin(), d->end());
        if (nofatchain) {
            ++c;
        } else {
            if (!seen.insert(c).second) break;
            uint32_t n = fat_next(fs, c);
            if (n < 2 || n >= 0xFFFFFFF7) break;
            c = n;
        }
    }
    return true;
}

std::string utf16_to_utf8(const std::vector<uint16_t>& u, size_t nchars) {
    std::string s;
    for (size_t i = 0; i < u.size() && i < nchars; ++i) {
        uint32_t cp = u[i];
        if (cp == 0) break;
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < u.size() && u[i + 1] >= 0xDC00 &&
            u[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (u[++i] - 0xDC00);
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
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

struct Ctx {
    const Fs& fs;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t entries = 0;
    std::set<uint32_t> dir_stack{};
};

void walk_dir(Ctx& c, const std::vector<uint8_t>& dir, const std::string& rel, size_t depth);

void walk_dir(Ctx& c, const std::vector<uint8_t>& dir, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    for (size_t off = 0; off + 32 <= dir.size(); off += 32) {
        if (c.entries++ > MAX_ENTRIES) { c.truncated = true; return; }
        const uint8_t* e = dir.data() + off;
        const uint8_t type = e[0];
        if (type == 0x00) break;             // end of directory
        if (!(type & 0x80)) continue;        // not in use (deleted)
        if (type != ENTRY_FILE) continue;    // only File entries start a set

        const uint8_t secondary = e[1];
        uint16_t attr;
        std::memcpy(&attr, e + 4, 2);
        // The stream extension is the next entry; name entries follow it.
        const size_t stream_off = off + 32;
        if (stream_off + 32 > dir.size() || dir[stream_off] != ENTRY_STREAM) continue;
        const uint8_t* se = dir.data() + stream_off;
        const uint8_t sflags = se[1];
        const uint8_t namelen = se[3];
        uint32_t first_cluster;
        uint64_t data_len;
        std::memcpy(&first_cluster, se + 20, 4);
        std::memcpy(&data_len, se + 24, 8);

        // Collect the name from the 0xC1 entries.
        std::vector<uint16_t> name16;
        const int name_entries = (secondary >= 1) ? secondary - 1 : 0;
        for (int k = 0; k < name_entries; ++k) {
            const size_t no = off + 64 + size_t(k) * 32;  // after File + Stream
            if (no + 32 > dir.size() || dir[no] != ENTRY_NAME) break;
            for (int j = 0; j < 15; ++j) {
                uint16_t ch;
                std::memcpy(&ch, dir.data() + no + 2 + j * 2, 2);
                name16.push_back(ch);
            }
        }
        off += size_t(secondary) * 32;  // consume the whole entry set

        std::string name = utf16_to_utf8(name16, namelen);
        if (name.empty() || name == "." || name == ".." || name.find('/') != std::string::npos)
            continue;
        const bool nofc = (sflags & STREAM_NOFATCHAIN) != 0;
        const std::string child_rel = rel.empty() ? name : rel + "/" + name;
        const std::string full = c.subdir + "/" + child_rel;

        if (attr & ATTR_DIR) {
            if (first_cluster < 2) continue;
            if (!c.dir_stack.insert(first_cluster).second) continue;  // cycle guard
            if (c.root.make_dir(full)) c.out.dirs++;
            std::vector<uint8_t> sub;
            if (read_run(c.fs, first_cluster, nofc, MAX_DIR_BYTES, sub))
                walk_dir(c, sub, child_rel, depth + 1);
            else
                c.truncated = true;
            c.dir_stack.erase(first_cluster);
        } else {
            uint64_t want = std::min<uint64_t>(data_len, MAX_FILE_BYTES);
            std::vector<uint8_t> data;
            if (want > 0 && first_cluster >= 2) {
                if (!read_run(c.fs, first_cluster, nofc, want, data)) { c.truncated = true; continue; }
                if (data.size() > want) data.resize(static_cast<size_t>(want));
            }
            if (c.root.write_file(full, data, 0644)) {
                c.out.files++;
                c.out.bytes += data.size();
            } else {
                c.out.warnings.push_back("write failed: " + child_rel);
            }
        }
    }
}

}  // namespace

bool extract_exfat(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out) {
    out.offset = f.offset;
    out.type = "exfat";
    out.root = subdir;
    const uint64_t base = f.offset;

    auto fat_offset = u32(r, base + 80);
    auto heap_offset = u32(r, base + 88);
    auto cluster_count = u32(r, base + 92);
    auto root_cluster = u32(r, base + 96);
    auto bps_shift = r.bytes(base + 108, 1);
    auto spc_shift = r.bytes(base + 109, 1);
    if (!fat_offset || !heap_offset || !cluster_count || !root_cluster || !bps_shift || !spc_shift) {
        out.status = "error:bad-boot";
        return true;
    }
    const uint32_t bps_sh = (*bps_shift)[0];
    const uint32_t spc_sh = (*spc_shift)[0];
    if (bps_sh < 9 || bps_sh > 12 || spc_sh > 25 || bps_sh + spc_sh > 25) {
        out.status = "error:bad-boot";
        return true;
    }
    const uint64_t bytes_per_sec = uint64_t(1) << bps_sh;
    Fs fs{r,
          base,
          base + uint64_t(*fat_offset) * bytes_per_sec,
          base + uint64_t(*heap_offset) * bytes_per_sec,
          *cluster_count,
          uint64_t(1) << (bps_sh + spc_sh)};

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    Ctx c{fs, root, subdir, out};
    std::vector<uint8_t> root_dir;
    if (!read_run(fs, *root_cluster, false, MAX_DIR_BYTES, root_dir)) {
        out.status = "error:root";
        return true;
    }
    walk_dir(c, root_dir, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

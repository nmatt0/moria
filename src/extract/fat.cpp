// fat.cpp — FAT extraction. See fat.hpp.
#include "extract/fat.hpp"

#include <algorithm>
#include <cstdint>
#include <cctype>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint8_t ATTR_DIR = 0x10;
constexpr uint8_t ATTR_VOLUME = 0x08;
constexpr uint8_t ATTR_LFN = 0x0F;

constexpr size_t MAX_ENTRIES = 4000000;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;
constexpr size_t MAX_DEPTH = 128;

enum class FatType { F12, F16, F32 };

struct Fs {
    const Reader& r;
    uint64_t base;
    uint32_t bytes_per_sec;
    uint32_t sec_per_clus;
    uint32_t reserved;
    uint32_t num_fats;
    uint32_t root_entries;
    uint32_t fat_size;       // sectors per FAT
    uint32_t first_data_sec;
    uint32_t root_dir_sec;   // FAT12/16 fixed root sector count
    uint32_t count_clusters;
    uint32_t root_cluster;   // FAT32
    FatType type;
    uint64_t clus_bytes;     // sec_per_clus * bytes_per_sec
};

std::optional<uint16_t> u16(const Reader& r, uint64_t o) { return r.at<uint16_t>(o, Endian::Little); }
std::optional<uint32_t> u32(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Little); }

// Next cluster in the FAT chain, or 0 on end/bad/error.
uint32_t fat_next(const Fs& fs, uint32_t cluster) {
    const uint64_t fat_off = fs.base + uint64_t(fs.reserved) * fs.bytes_per_sec;
    if (fs.type == FatType::F12) {
        const uint64_t o = fat_off + cluster + cluster / 2;
        auto v = u16(fs.r, o);
        if (!v) return 0;
        uint32_t e = (cluster & 1) ? (*v >> 4) : (*v & 0x0FFF);
        return (e >= 0xFF8) ? 0 : e;
    }
    if (fs.type == FatType::F16) {
        auto v = u16(fs.r, fat_off + uint64_t(cluster) * 2);
        if (!v) return 0;
        return (*v >= 0xFFF8) ? 0 : *v;
    }
    auto v = u32(fs.r, fat_off + uint64_t(cluster) * 4);
    if (!v) return 0;
    uint32_t e = *v & 0x0FFFFFFF;
    return (e >= 0x0FFFFFF8) ? 0 : e;
}

uint64_t cluster_offset(const Fs& fs, uint32_t cluster) {
    return fs.base + (uint64_t(fs.first_data_sec) + uint64_t(cluster - 2) * fs.sec_per_clus) *
                         fs.bytes_per_sec;
}

// Read a cluster chain (following the FAT) into `out`, capped at `cap` bytes.
// A cycle/visited guard bounds runaway chains.
bool read_chain(const Fs& fs, uint32_t first, uint64_t cap, std::vector<uint8_t>& out) {
    out.clear();
    uint32_t c = first;
    std::set<uint32_t> seen;
    while (c >= 2 && c < fs.count_clusters + 2 && out.size() < cap) {
        if (!seen.insert(c).second) break;  // cycle
        auto d = fs.r.bytes(static_cast<size_t>(cluster_offset(fs, c)),
                            static_cast<size_t>(fs.clus_bytes));
        if (!d) return false;
        out.insert(out.end(), d->begin(), d->end());
        c = fat_next(fs, c);
    }
    return true;
}

// Decode a UTF-16LE code-unit sequence (from assembled LFN pieces) to UTF-8,
// stopping at NUL. Lone surrogates are passed through as U+FFFD.
std::string utf16_to_utf8(const std::vector<uint16_t>& u) {
    std::string s;
    for (size_t i = 0; i < u.size(); ++i) {
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

// The 8.3 short name from a directory entry, honoring the lowercase flags.
std::string short_name(const uint8_t* e) {
    std::string base, ext;
    for (int i = 0; i < 8; ++i)
        if (e[i] != ' ') base += static_cast<char>(e[i]);
    for (int i = 8; i < 11; ++i)
        if (e[i] != ' ') ext += static_cast<char>(e[i]);
    if (e[12] & 0x08)
        for (auto& c : base) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (e[12] & 0x10)
        for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (base.size() && static_cast<uint8_t>(base[0]) == 0x05) base[0] = static_cast<char>(0xE5);
    return ext.empty() ? base : base + "." + ext;
}

struct Ctx {
    const Fs& fs;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t entries = 0;
    std::set<uint32_t> dir_stack{};  // cluster cycle guard across directory recursion
};

void walk_dir(Ctx& c, const std::vector<uint8_t>& dir, const std::string& rel, size_t depth);

// Extract a directory (root or subdir) given its raw bytes.
void walk_dir(Ctx& c, const std::vector<uint8_t>& dir, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    std::vector<uint16_t> lfn;  // assembled long-name code units (in order)
    bool have_lfn = false;

    for (size_t off = 0; off + 32 <= dir.size(); off += 32) {
        if (c.entries++ > MAX_ENTRIES) { c.truncated = true; return; }
        const uint8_t* e = dir.data() + off;
        if (e[0] == 0x00) break;         // end of directory
        if (e[0] == 0xE5) { have_lfn = false; lfn.clear(); continue; }  // deleted
        const uint8_t attr = e[11];
        if (attr == ATTR_LFN) {
            // LFN pieces: seq in e[0] (bit 0x40 = last, i.e. highest fragment).
            const uint32_t seq = e[0] & 0x1F;
            if (seq == 0 || seq > 20) continue;
            uint16_t chunk[13];
            const int idx[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
            for (int i = 0; i < 13; ++i) std::memcpy(&chunk[i], e + idx[i], 2);
            const size_t pos = (seq - 1) * 13;
            if (lfn.size() < pos + 13) lfn.resize(pos + 13, 0);
            for (int i = 0; i < 13; ++i) lfn[pos + i] = chunk[i];
            have_lfn = true;
            continue;
        }
        if (attr & ATTR_VOLUME) { have_lfn = false; lfn.clear(); continue; }  // volume label

        std::string name = have_lfn ? utf16_to_utf8(lfn) : short_name(e);
        have_lfn = false;
        lfn.clear();
        if (name.empty() || name == "." || name == ".." || name.find('/') != std::string::npos)
            continue;

        uint16_t hi, lo, dummy16;
        uint32_t size;
        std::memcpy(&dummy16, e + 20, 2);
        hi = dummy16;
        std::memcpy(&lo, e + 26, 2);
        std::memcpy(&size, e + 28, 4);
        const uint32_t first = (uint32_t(hi) << 16) | lo;
        const std::string child_rel = rel.empty() ? name : rel + "/" + name;
        const std::string full = c.subdir + "/" + child_rel;

        if (attr & ATTR_DIR) {
            if (first < 2) continue;
            if (!c.dir_stack.insert(first).second) continue;  // cycle guard
            if (c.root.make_dir(full)) c.out.dirs++;
            std::vector<uint8_t> sub;
            if (read_chain(c.fs, first, uint64_t(64) << 20, sub))
                walk_dir(c, sub, child_rel, depth + 1);
            else
                c.truncated = true;
            c.dir_stack.erase(first);
        } else {
            uint64_t want = std::min<uint64_t>(size, MAX_FILE_BYTES);
            std::vector<uint8_t> data;
            if (first == 0 || size == 0) {
                data.clear();  // empty file
            } else if (!read_chain(c.fs, first, want, data)) {
                c.truncated = true;
                continue;
            }
            if (data.size() > want) data.resize(static_cast<size_t>(want));
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

bool extract_fat(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.offset = f.offset;
    out.type = "fat";
    out.root = subdir;
    const uint64_t base = f.offset;

    auto bps = u16(r, base + 11);
    auto spc = r.bytes(base + 13, 1);
    auto rsv = u16(r, base + 14);
    auto nfat = r.bytes(base + 16, 1);
    auto rent = u16(r, base + 17);
    auto tot16 = u16(r, base + 19);
    auto fsz16 = u16(r, base + 22);
    auto tot32 = u32(r, base + 32);
    auto fsz32 = u32(r, base + 36);
    auto rclus = u32(r, base + 44);
    if (!bps || !spc || !rsv || !nfat || !rent || !tot16 || !fsz16 || !tot32 || !fsz32 || !rclus) {
        out.status = "error:bad-bpb";
        return true;
    }
    const uint32_t bytes_per_sec = *bps;
    const uint32_t sec_per_clus = (*spc)[0];
    if (bytes_per_sec < 512 || (bytes_per_sec & (bytes_per_sec - 1)) || sec_per_clus == 0 ||
        (sec_per_clus & (sec_per_clus - 1)) || (*nfat)[0] == 0) {
        out.status = "error:bad-bpb";
        return true;
    }
    const uint32_t fat_size = *fsz16 ? *fsz16 : *fsz32;
    const uint32_t total_sec = *tot16 ? *tot16 : *tot32;
    const uint32_t root_dir_sec = ((uint32_t(*rent) * 32) + bytes_per_sec - 1) / bytes_per_sec;
    const uint32_t first_data_sec = *rsv + uint32_t((*nfat)[0]) * fat_size + root_dir_sec;
    if (fat_size == 0 || total_sec < first_data_sec) {
        out.status = "error:bad-bpb";
        return true;
    }
    const uint32_t data_sec = total_sec - first_data_sec;
    const uint32_t count_clusters = data_sec / sec_per_clus;

    Fs fs{r,
          base,
          bytes_per_sec,
          sec_per_clus,
          *rsv,
          (*nfat)[0],
          *rent,
          fat_size,
          first_data_sec,
          root_dir_sec,
          count_clusters,
          *rclus,
          FatType::F16,
          uint64_t(sec_per_clus) * bytes_per_sec};
    fs.type = (count_clusters < 4085) ? FatType::F12
              : (count_clusters < 65525) ? FatType::F16
                                         : FatType::F32;

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    Ctx c{fs, root, subdir, out};

    std::vector<uint8_t> root_dir;
    if (fs.type == FatType::F32) {
        if (!read_chain(fs, fs.root_cluster, uint64_t(64) << 20, root_dir)) {
            out.status = "error:root";
            return true;
        }
    } else {
        // Widen before multiplying: a hostile fat_size could overflow uint32 math.
        const uint64_t ro =
            base + (uint64_t(*rsv) + uint64_t((*nfat)[0]) * fat_size) * uint64_t(bytes_per_sec);
        auto d = r.bytes(static_cast<size_t>(ro), static_cast<size_t>(uint32_t(*rent) * 32));
        if (!d) {
            out.status = "error:root";
            return true;
        }
        root_dir.assign(d->begin(), d->end());
    }
    walk_dir(c, root_dir, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

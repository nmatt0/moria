// ntfs.cpp — NTFS extraction. See ntfs.hpp.
#include "extract/ntfs.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint32_t ATTR_FILE_NAME = 0x30;
constexpr uint32_t ATTR_DATA = 0x80;
constexpr uint32_t ATTR_REPARSE_POINT = 0xC0;  // symlinks/junctions
constexpr uint32_t ATTR_END = 0xFFFFFFFF;

constexpr uint16_t FLAG_IN_USE = 0x0001;
constexpr uint16_t FLAG_DIR = 0x0002;

constexpr uint64_t ROOT_REF = 5;      // MFT record 5 = root directory
constexpr uint64_t FIRST_USER = 16;   // records 0..15 are system metadata
constexpr size_t MAX_RECORDS = 8000000;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;
constexpr uint64_t MAX_MFT_BYTES = uint64_t(2) << 30;

struct RunEntry {
    int64_t lcn;   // -1 = sparse hole
    uint64_t len;  // clusters
};

struct Entry {
    std::string name;
    uint64_t parent = 0;
    bool is_dir = false;
    bool has_data = false;
    bool resident = false;
    std::vector<uint8_t> resident_data;
    std::vector<RunEntry> runs;
    uint64_t data_size = 0;
    bool reparse = false;
};

// Apply the NTFS Update Sequence Array fixup to an in-memory record.
void apply_fixup(std::vector<uint8_t>& rec) {
    if (rec.size() < 8) return;
    uint16_t uofs, ucnt;
    std::memcpy(&uofs, rec.data() + 4, 2);
    std::memcpy(&ucnt, rec.data() + 6, 2);
    if (uofs + size_t(ucnt) * 2 > rec.size() || ucnt == 0) return;
    for (uint16_t i = 1; i < ucnt; ++i) {
        const size_t pos = size_t(i) * 512 - 2;
        if (pos + 2 > rec.size()) break;
        std::memcpy(rec.data() + pos, rec.data() + uofs + size_t(i) * 2, 2);
    }
}

// Decode a runlist starting at `off` within `rec`. LCNs are delta-encoded.
std::vector<RunEntry> parse_runlist(const uint8_t* rec, size_t len, size_t off) {
    std::vector<RunEntry> runs;
    int64_t lcn = 0;
    size_t p = off;
    while (p < len && rec[p] != 0 && runs.size() < 1u << 20) {
        const uint8_t hdr = rec[p++];
        const uint8_t lsz = hdr & 0xF;
        const uint8_t osz = hdr >> 4;
        if (lsz == 0 || p + lsz + osz > len) break;
        uint64_t length = 0;
        for (int i = 0; i < lsz; ++i) length |= uint64_t(rec[p + i]) << (8 * i);
        p += lsz;
        if (osz == 0) {
            runs.push_back({-1, length});  // sparse
        } else {
            int64_t off_v = 0;
            for (int i = 0; i < osz; ++i) off_v |= int64_t(rec[p + i]) << (8 * i);
            if (rec[p + osz - 1] & 0x80)  // sign-extend
                off_v |= -(int64_t(1) << (8 * osz));
            p += osz;
            lcn += off_v;
            runs.push_back({lcn, length});
        }
    }
    return runs;
}

struct Ntfs {
    const Reader& r;
    uint64_t base;
    uint64_t cluster_bytes;
    std::vector<uint8_t> mft;  // the full $MFT $DATA
    uint32_t rec_size;
};

// Read a runlist's data (from the raw image) up to `size` bytes.
std::vector<uint8_t> read_runs(const Ntfs& fs, const std::vector<RunEntry>& runs, uint64_t size) {
    std::vector<uint8_t> out;
    out.reserve(static_cast<size_t>(std::min<uint64_t>(size, MAX_FILE_BYTES)));
    for (const auto& run : runs) {
        if (out.size() >= size) break;
        const uint64_t bytes = run.len * fs.cluster_bytes;
        if (run.lcn < 0) {
            const uint64_t n = std::min<uint64_t>(bytes, size - out.size());
            out.insert(out.end(), static_cast<size_t>(n), 0);
        } else {
            const uint64_t off = fs.base + uint64_t(run.lcn) * fs.cluster_bytes;
            const uint64_t n = std::min<uint64_t>(bytes, size - out.size());
            auto d = fs.r.bytes(static_cast<size_t>(off), static_cast<size_t>(n));
            if (!d) break;
            out.insert(out.end(), d->begin(), d->end());
        }
    }
    if (out.size() > size) out.resize(static_cast<size_t>(size));
    return out;
}

// Parse one MFT record's attributes into an Entry. Returns false if not a valid
// in-use file record.
bool parse_record(std::vector<uint8_t> rec, Entry& e) {
    if (rec.size() < 24 || std::memcmp(rec.data(), "FILE", 4) != 0) return false;
    apply_fixup(rec);
    uint16_t flags, attrs_off;
    std::memcpy(&attrs_off, rec.data() + 0x14, 2);
    std::memcpy(&flags, rec.data() + 0x16, 2);
    if (!(flags & FLAG_IN_USE)) return false;
    e.is_dir = (flags & FLAG_DIR) != 0;

    int best_ns = -1;
    size_t p = attrs_off;
    while (p + 8 <= rec.size()) {
        uint32_t type, alen;
        std::memcpy(&type, rec.data() + p, 4);
        std::memcpy(&alen, rec.data() + p + 4, 4);
        if (type == ATTR_END) break;
        if (alen < 24 || p + alen > rec.size()) break;
        const uint8_t nonres = rec[p + 8];
        const uint8_t name_len = rec[p + 9];
        uint16_t aflags;
        std::memcpy(&aflags, rec.data() + p + 0x0C, 2);

        if (type == ATTR_FILE_NAME && !nonres) {
            uint32_t vlen;
            uint16_t vofs;
            std::memcpy(&vlen, rec.data() + p + 0x10, 4);
            std::memcpy(&vofs, rec.data() + p + 0x14, 2);
            const size_t v = p + vofs;
            if (v + 0x42 <= rec.size() && vlen >= 0x42) {
                uint64_t parent;
                std::memcpy(&parent, rec.data() + v, 8);
                parent &= (uint64_t(1) << 48) - 1;
                const uint8_t nl = rec[v + 0x40];
                const uint8_t ns = rec[v + 0x41];
                if (ns != 2 && ns > best_ns && v + 0x42 + size_t(nl) * 2 <= rec.size()) {
                    // UTF-16LE -> UTF-8
                    std::string name;
                    for (size_t i = 0; i < nl; ++i) {
                        uint16_t ch;
                        std::memcpy(&ch, rec.data() + v + 0x42 + i * 2, 2);
                        if (ch < 0x80) {
                            name += static_cast<char>(ch);
                        } else if (ch < 0x800) {
                            name += static_cast<char>(0xC0 | (ch >> 6));
                            name += static_cast<char>(0x80 | (ch & 0x3F));
                        } else {
                            name += static_cast<char>(0xE0 | (ch >> 12));
                            name += static_cast<char>(0x80 | ((ch >> 6) & 0x3F));
                            name += static_cast<char>(0x80 | (ch & 0x3F));
                        }
                    }
                    best_ns = ns;
                    e.name = name;
                    e.parent = parent;
                }
            }
        } else if (type == ATTR_REPARSE_POINT) {
            e.reparse = true;  // symlink / junction / mount point
        } else if (type == ATTR_DATA && name_len == 0) {
            (void)aflags;
            if (nonres) {
                uint16_t rlo;
                uint64_t real;
                std::memcpy(&rlo, rec.data() + p + 0x20, 2);
                std::memcpy(&real, rec.data() + p + 0x30, 8);
                if (p + rlo < p + alen) {
                    e.runs = parse_runlist(rec.data() + p, p + alen, rlo);
                    e.data_size = real;
                    e.resident = false;
                    e.has_data = true;
                }
            } else {
                uint32_t vlen;
                uint16_t vofs;
                std::memcpy(&vlen, rec.data() + p + 0x10, 4);
                std::memcpy(&vofs, rec.data() + p + 0x14, 2);
                if (p + vofs + vlen <= rec.size()) {
                    e.resident_data.assign(rec.data() + p + vofs, rec.data() + p + vofs + vlen);
                    e.resident = true;
                    e.has_data = true;
                }
            }
        }
        p += alen;
    }
    return !e.name.empty();
}

}  // namespace

bool extract_ntfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out) {
    out.offset = f.offset;
    out.type = "ntfs";
    out.root = subdir;
    const uint64_t base = f.offset;

    auto bps = r.at<uint16_t>(base + 11, Endian::Little);
    auto spc = r.bytes(base + 13, 1);
    auto mft_clus = r.at<uint64_t>(base + 48, Endian::Little);
    auto cpm_b = r.bytes(base + 64, 1);
    if (!bps || !spc || !mft_clus || !cpm_b) {
        out.status = "error:bad-boot";
        return true;
    }
    const uint32_t bytes_per_sec = *bps;
    const uint32_t sec_per_clus = (*spc)[0];
    if (bytes_per_sec < 256 || (bytes_per_sec & (bytes_per_sec - 1)) || sec_per_clus == 0 ||
        (sec_per_clus & (sec_per_clus - 1))) {
        out.status = "error:bad-boot";
        return true;
    }
    const int8_t cpm = static_cast<int8_t>((*cpm_b)[0]);
    const uint64_t cluster_bytes = uint64_t(bytes_per_sec) * sec_per_clus;
    const uint32_t rec_size =
        cpm < 0 ? (uint32_t(1) << (-cpm)) : uint32_t(cpm) * static_cast<uint32_t>(cluster_bytes);
    if (rec_size < 512 || rec_size > 65536) {
        out.status = "error:bad-boot";
        return true;
    }

    Ntfs fs{r, base, cluster_bytes, {}, rec_size};

    // Read MFT record 0 ($MFT), then its $DATA runlist gives the whole MFT.
    const uint64_t mft_off = base + *mft_clus * cluster_bytes;
    auto rec0 = r.bytes(static_cast<size_t>(mft_off), rec_size);
    if (!rec0) {
        out.status = "error:no-mft";
        return true;
    }
    Entry mft_entry;
    if (!parse_record(std::vector<uint8_t>(rec0->begin(), rec0->end()), mft_entry) ||
        !mft_entry.has_data || mft_entry.resident) {
        out.status = "error:no-mft";
        return true;
    }
    uint64_t mft_size = std::min<uint64_t>(mft_entry.data_size, MAX_MFT_BYTES);
    fs.mft = read_runs(fs, mft_entry.runs, mft_size);
    const uint64_t nrec = fs.mft.size() / rec_size;
    if (nrec == 0) {
        out.status = "error:no-mft";
        return true;
    }

    // Pass 1: collect every in-use file record.
    std::map<uint64_t, Entry> entries;
    for (uint64_t n = 0; n < nrec && n < MAX_RECORDS; ++n) {
        std::vector<uint8_t> rec(fs.mft.begin() + n * rec_size, fs.mft.begin() + (n + 1) * rec_size);
        Entry e;
        if (parse_record(std::move(rec), e)) entries.emplace(n, std::move(e));
    }

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    bool truncated = false;

    // Reconstruct the path of a record by walking parent references to the root.
    auto path_of = [&](uint64_t n) -> std::optional<std::string> {
        std::vector<std::string> parts;
        uint64_t cur = n;
        std::vector<uint64_t> seen;
        for (int depth = 0; depth < 256; ++depth) {
            if (cur == ROOT_REF) {
                std::string path;
                for (auto it = parts.rbegin(); it != parts.rend(); ++it)
                    path += (path.empty() ? "" : "/") + *it;
                return path;
            }
            auto it = entries.find(cur);
            if (it == entries.end()) return std::nullopt;
            if (std::find(seen.begin(), seen.end(), cur) != seen.end()) return std::nullopt;
            seen.push_back(cur);
            const std::string& nm = it->second.name;
            if (nm.empty() || nm[0] == '$' || nm == "." || nm.find('/') != std::string::npos)
                return std::nullopt;  // system file or unsafe
            parts.push_back(nm);
            cur = it->second.parent;
        }
        return std::nullopt;
    };

    // Pass 2: write.
    for (auto& [n, e] : entries) {
        if (n < FIRST_USER) continue;  // system metadata
        if (e.reparse) continue;       // symlink/junction reparse points
        auto path = path_of(n);
        if (!path || path->empty()) continue;
        const std::string full = subdir + "/" + *path;
        if (e.is_dir) {
            if (root.make_dir(full)) out.dirs++;
            continue;
        }
        std::vector<uint8_t> data;
        if (e.has_data) {
            if (e.resident)
                data = e.resident_data;
            else
                data = read_runs(fs, e.runs, std::min<uint64_t>(e.data_size, MAX_FILE_BYTES));
        }
        if (root.write_file(full, data, 0644)) {
            out.files++;
            out.bytes += data.size();
        } else {
            out.warnings.push_back("write failed: " + *path);
        }
    }

    out.status = truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

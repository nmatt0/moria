// rae_rfp.cpp — RAE Systems / Honeywell RFP section extraction. See rae_rfp.hpp.
//
// Header is 0x29 bytes; the section table then repeats to EOF:
//   u32 name_len; char name[name_len]; u32 flags; u32 usize; u32 csize; u8 data[csize]
// flags: 0 = stored, 1 = LZARI-compressed (data is a whole lzari stream whose own
// 4-byte prefix equals usize). One output file per section, named for the section.
#include "extract/rae_rfp.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "extract/lzari.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr size_t kHeader = 0x29;
constexpr size_t kMaxName = 64;
constexpr size_t kMaxSections = 256;
constexpr uint64_t kMaxSection = uint64_t(256) << 20;  // 256 MiB per decoded section

// Keep section names to a safe, flat filename (they are already IniFile/HexFile/
// BinFile/SIGN in practice; this just hardens against anything odd).
std::string sanitize(const std::string& name) {
    std::string s;
    for (char c : name) {
        unsigned char u = static_cast<unsigned char>(c);
        s += (u == '.' || u == '_' || u == '-' ||
              (u >= '0' && u <= '9') || (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z'))
                 ? c : '_';
    }
    if (s.empty()) s = "section";
    return s;
}

}  // namespace

bool extract_rae_rfp(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                     Extracted& out) {
    out.offset = f.offset;
    out.type = "rae_rfp";
    out.root = subdir;

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    size_t off = f.offset + kHeader;
    size_t count = 0;
    bool any_fail = false;
    std::unordered_map<std::string, int> used;  // filename collision guard

    while (count < kMaxSections) {
        auto name_len = r.at<uint32_t>(off, Endian::Little);
        if (!name_len || *name_len == 0 || *name_len > kMaxName) break;
        auto name = r.bytes(off + 4, *name_len);
        if (!name) break;

        const size_t p = off + 4 + *name_len;
        auto flags = r.at<uint32_t>(p, Endian::Little);
        auto usize = r.at<uint32_t>(p + 4, Endian::Little);
        auto csize = r.at<uint32_t>(p + 8, Endian::Little);
        if (!flags || !usize || !csize || *flags > 1) break;

        const size_t data_off = p + 12;
        auto src = r.bytes(data_off, *csize);
        if (!src) break;  // section runs past EOF

        std::string fname = sanitize(std::string(reinterpret_cast<const char*>(name->data()), name->size()));
        if (int& n = used[fname]; n++ > 0) fname += "_" + std::to_string(n);

        std::vector<uint8_t> data;
        if (*flags == 1) {
            auto d = lzari_decompress(*src, kMaxSection);
            if (d && d->size() == *usize) {
                data = std::move(*d);
            } else {
                // Decode failed or size mismatch: keep the raw compressed bytes so
                // nothing is lost, and flag it.
                data.assign(src->begin(), src->end());
                any_fail = true;
                out.warnings.push_back(fname + ": lzari decode failed, stored raw");
            }
        } else {
            data.assign(src->begin(), src->end());
        }

        if (root.write_file(subdir + "/" + fname, data, 0644)) {
            out.files++;
            out.bytes += data.size();
        } else {
            out.status = "error:write";
            return true;
        }

        off = data_off + *csize;
        ++count;
        if (off >= r.size()) break;
    }

    out.consumed = (off > f.offset) ? (off - f.offset) : 0;
    if (count == 0)
        out.status = "error:no-sections";
    else
        out.status = any_fail ? "partial" : "ok";
    return true;
}

}  // namespace ft

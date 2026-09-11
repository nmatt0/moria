// vbf.cpp — VBF (Versatile Binary Format) block extraction. See vbf.hpp.
//
// After the ASCII header the block chain repeats to EOF:
//   u32 be start; u32 be len; u8 data[len]; u16 be crc16
// data_format_identifier upper nibble != 0 -> each block is an LZSS stream whose
// CRC16 covers the decoded bytes. One output file per block, named for its load
// address.
#include "extract/vbf.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "crc16.hpp"
#include "extract/lzss.hpp"
#include "extract/safepath.hpp"
#include "vbf_header.hpp"

namespace ft {

namespace {
constexpr size_t kMaxBlocks = 4096;
constexpr uint64_t kMaxBlock = uint64_t(256) << 20;  // 256 MiB decoded per block

std::string addr_name(size_t idx, uint32_t addr) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "block%zu_0x%08X.bin", idx, addr);
    return std::string(buf);
}
}  // namespace

bool extract_vbf(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.offset = f.offset;
    out.type = "vbf";
    out.root = subdir;

    auto he = vbf::header_end(r, f.offset);
    if (!he) {
        out.status = "error:bad-header";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    const uint8_t dfi = vbf::data_format(r, f.offset, *he);
    const bool compressed = vbf::is_compressed(dfi);

    size_t off = *he;
    size_t count = 0;
    bool any_fail = false;
    while (count < kMaxBlocks) {
        auto start = r.at<uint32_t>(off, Endian::Big);
        auto len = r.at<uint32_t>(off + 4, Endian::Big);
        if (!start || !len || *len == 0) break;
        const size_t data_off = off + 8;
        if (*len > r.size() - data_off) break;
        if (*len + 2 > r.size() - data_off) break;
        auto src = r.bytes(data_off, *len);
        auto crc_stored = r.at<uint16_t>(data_off + *len, Endian::Big);
        if (!src || !crc_stored) break;

        std::string fname = addr_name(count, *start);
        std::vector<uint8_t> data;
        if (compressed) {
            auto d = lzss_vbf_decompress(*src, kMaxBlock);
            if (d && crc16_ccitt(*d) == *crc_stored) {
                data = std::move(*d);
            } else {
                // Decode failed or CRC mismatch: keep the raw compressed bytes so
                // nothing is lost, and flag it.
                data.assign(src->begin(), src->end());
                any_fail = true;
                out.warnings.push_back(fname + ": lzss decode/crc failed, stored raw");
            }
        } else {
            data.assign(src->begin(), src->end());
            if (crc16_ccitt(data) != *crc_stored) {
                any_fail = true;
                out.warnings.push_back(fname + ": crc16 mismatch");
            }
        }

        if (root.write_file(subdir + "/" + fname, data, 0644)) {
            out.files++;
            out.bytes += data.size();
        } else {
            out.status = "error:write";
            return true;
        }

        off = data_off + *len + 2;
        ++count;
        if (off >= r.size()) break;
    }

    out.consumed = (off > f.offset) ? (off - f.offset) : 0;
    if (count == 0)
        out.status = "error:no-blocks";
    else
        out.status = any_fail ? "partial" : "ok";
    return true;
}

}  // namespace ft

// vfw.cpp — VFW firmware container extraction. See vfw.hpp.
//
// Re-reads the header fields directly (matching this codebase's convention).
// Writes: payload.bin (the raw firmware payload, payload_size bytes starting
// at offset 16). The CRC-32 is verified; a mismatch is a warning, not an
// error, since the payload is still usable for analysis.
#include "extract/vfw.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "crc32.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {
constexpr size_t kHeader = 16;

std::string payload_name(const Reader& r, size_t base) {
    auto comp = r.bytes(base + 3, 3);
    auto var = r.bytes(base + 6, 2);
    if (!comp || !var) return "payload.bin";

    char buf[16];
    bool comp_ok = true, var_ok = true;
    for (auto b : *comp)
        if (b < 0x20 || b >= 0x7f) { comp_ok = false; break; }
    for (auto b : *var)
        if (b < 0x20 || b >= 0x7f) { var_ok = false; break; }

    if (comp_ok && var_ok) {
        std::snprintf(buf, sizeof(buf), "%.3s_%.2s.bin",
                      reinterpret_cast<const char*>(comp->data()),
                      reinterpret_cast<const char*>(var->data()));
        return std::string(buf);
    }
    return "payload.bin";
}
}  // namespace

bool extract_vfw(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.offset = f.offset;
    out.type = "vfw";
    out.root = subdir;

    auto payload_size = r.at<uint32_t>(f.offset + 8, Endian::Little);
    auto crc_stored = r.at<uint32_t>(f.offset + 12, Endian::Little);
    if (!payload_size || !crc_stored || *payload_size == 0) {
        out.status = "error:bad-header";
        return true;
    }

    auto payload = r.bytes(f.offset + kHeader, *payload_size);
    if (!payload) {
        out.status = "error:truncated";
        return true;
    }

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    uint32_t crc_actual = crc32_ieee(*payload);
    bool crc_ok = (crc_actual == *crc_stored);

    std::string fname = payload_name(r, f.offset);
    std::vector<uint8_t> data(payload->begin(), payload->end());
    if (!root.write_file(subdir + "/" + fname, data, 0644)) {
        out.status = "error:write";
        return true;
    }
    out.files++;
    out.bytes += data.size();
    out.consumed = kHeader + *payload_size;

    if (!crc_ok)
        out.warnings.push_back(fname + ": CRC-32 mismatch");

    out.status = crc_ok ? "ok" : "partial";
    return true;
}

}  // namespace ft

// vfw.cpp — VFW firmware container validator.
//
// Layout (all integers little-endian):
//   0x00  bytes[3]  prefix         "VFW"
//   0x03  bytes[3]  component      "MCU" / "BLE" / "GPS" / "WFS"
//   0x06  bytes[2]  variant        device/generation identifier (ASCII)
//   0x08  u32       payload_size
//   0x0C  u32       crc32          IEEE CRC-32 over payload (bytes 16..16+payload_size)
//   0x10  ...       payload        payload_size bytes of raw firmware
// CRC-32 verified over payload -> verified; payload_size spans to EOF ->
// consistent; header parsed -> structural.
#include "validators/vfw.hpp"

#include <algorithm>
#include <string>

#include "crc32.hpp"

namespace ft {

namespace {
constexpr size_t kHeader = 16;
constexpr size_t kMagicLen = 8;

std::string ascii_label(const Reader& r, size_t off, size_t len) {
    auto b = r.bytes(off, len);
    if (!b) return "";
    std::string s(reinterpret_cast<const char*>(b->data()), len);
    if (!std::all_of(s.begin(), s.end(),
                     [](unsigned char c) { return c >= 0x20 && c < 0x7f; }))
        return "";
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}
}  // namespace

bool validate_vfw(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;

    static constexpr uint8_t kMagic[] = {'V', 'F', 'W'};
    if (!r.matches_at(base, kMagic)) return false;

    auto payload_size = r.at<uint32_t>(base + 8, Endian::Little);
    auto crc_stored = r.at<uint32_t>(base + 12, Endian::Little);
    if (!payload_size || !crc_stored) return false;
    if (*payload_size == 0) return false;

    const size_t avail = r.size() - base;
    if (kHeader > avail || *payload_size > avail - kHeader) return false;

    ctx.out.size = kHeader + *payload_size;
    ctx.out.endian = Endian::Little;

    std::string magic_str = ascii_label(r, base, kMagicLen);
    if (!magic_str.empty()) ctx.out.label = magic_str;

    std::string comp = ascii_label(r, base + 3, 3);
    if (!comp.empty()) {
        if (comp == "MCU") ctx.out.arch = "arm";
    }

    auto payload = r.bytes(base + kHeader, *payload_size);
    if (!payload) {
        ctx.out.set_confidence(Confidence::Structural, "header parsed, payload truncated");
        return true;
    }

    uint32_t crc_actual = crc32_ieee(*payload);
    bool exact_eof = (kHeader + *payload_size == avail);

    if (crc_actual == *crc_stored) {
        ctx.out.set_confidence(Confidence::Verified, "payload CRC-32 verified");
    } else if (exact_eof) {
        ctx.out.set_confidence(Confidence::Consistent, "payload spans file exactly, CRC mismatch");
    } else {
        ctx.out.set_confidence(Confidence::Structural, "header parsed");
    }
    return true;
}

}  // namespace ft

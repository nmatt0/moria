// uefi_fv.cpp — UEFI Firmware Volume refinement validator. See uefi_fv.hpp.
#include "validators/uefi_fv.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

namespace ft {

namespace {

uint64_t field(const FieldMap& f, const char* k) {
    auto it = f.find(k);
    return it == f.end() ? 0 : it->second;
}

// On-disk EFI_GUID byte layouts we recognize.
constexpr std::array<uint8_t, 16> kNvData = {0x8D, 0x2B, 0xF1, 0xFF, 0x96, 0x76, 0x8B, 0x4C,
                                             0xA9, 0x85, 0x27, 0x47, 0x07, 0x5B, 0x4F, 0x50};
constexpr std::array<uint8_t, 16> kFfs2 = {0x78, 0xE5, 0x8C, 0x8C, 0x3D, 0x8A, 0x1C, 0x4F,
                                           0x99, 0x35, 0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3};
constexpr std::array<uint8_t, 16> kFfs3 = {0x7A, 0xC0, 0x73, 0x54, 0xCB, 0x3D, 0xCA, 0x4D,
                                           0xBD, 0x6F, 0x1E, 0x96, 0x89, 0xE7, 0x34, 0x9A};

bool guid_eq(std::span<const uint8_t> b, const std::array<uint8_t, 16>& g) {
    return b.size() >= 16 && std::equal(g.begin(), g.end(), b.begin());
}

}  // namespace

bool validate_uefi_fv(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;
    const uint64_t header_length = field(ctx.fields, "header_length");
    if (header_length < 56 || header_length > 4096 || (header_length & 1)) return false;

    // 16-bit header checksum: the sum of every UINT16 in the header is zero.
    uint16_t sum = 0;
    for (uint64_t i = 0; i < header_length; i += 2) {
        auto w = r.at<uint16_t>(off + i, Endian::Little);
        if (!w) return false;
        sum = static_cast<uint16_t>(sum + *w);
    }
    if (sum != 0) return false;  // not a real FV header

    // Label by the filesystem GUID.
    std::string label = "ffs";
    if (auto g = r.bytes(off + 16, 16)) {
        if (guid_eq(*g, kNvData))
            label = "nvram (Secure Boot variables)";
        else if (guid_eq(*g, kFfs2) || guid_eq(*g, kFfs3))
            label = "ffs";
        else {
            char buf[40];
            std::snprintf(buf, sizeof(buf), "%08x-...", *r.at<uint32_t>(off + 16, Endian::Little));
            label = buf;
        }
    }
    ctx.out.label = label;
    ctx.out.set_confidence(Confidence::Verified, "UEFI firmware volume, header checksum ok");
    return true;
}

}  // namespace ft

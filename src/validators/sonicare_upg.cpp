// sonicare_upg.cpp — Philips Sonicare ".upg" firmware container validator.
//
// Layout (all integers little-endian):
//   0x00  bytes[4]  magic            FC 55 50 48
//   0x04  u32       reserved         constant 0xFFFFFFFF (enforced by constraint)
//   0x08  u32       payload_size
//   0x0C  u16       format_version   constant 1 (enforced by constraint)
//   0x0E  u16       header_length    constant 0x38 (enforced by constraint)
//   0x10  ...       unidentified, fills out header_length bytes
//   header_length            payload_size bytes of payload
//   header_length+payload_size   16-byte trailer, unidentified
//
// The payload's first 16 bytes are an opaque per-file value (nonce or digest);
// bytes 0x10-0x17 are a constant tag (01 00 14 01 02 00 00 00, identical across
// every sample); bytes 0x18+ are a NUL-padded ASCII label (component name).
#include "validators/sonicare_upg.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace ft {

namespace {
uint64_t field(const FieldMap& f, const char* k) {
    auto it = f.find(k);
    return it == f.end() ? 0 : it->second;
}

constexpr size_t kPreLabel = 24;   // 16 opaque + 8-byte tag
constexpr size_t kTrailer = 16;
constexpr size_t kMaxLabel = 64;
constexpr uint8_t kExpectedTag[8] = {0x01, 0x00, 0x14, 0x01, 0x02, 0x00, 0x00, 0x00};
}  // namespace

bool validate_sonicare_upg(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;

    const uint64_t header_length = field(ctx.fields, "header_length");
    const uint64_t payload_size = field(ctx.fields, "payload_size");
    const uint64_t total = header_length + payload_size + kTrailer;

    if (base > r.size() || total > r.size() - base) return false;
    ctx.out.size = total;

    // Extract the label, clamped to within the payload.
    if (payload_size > kPreLabel) {
        const size_t label_off = base + header_length + kPreLabel;
        const size_t avail = static_cast<size_t>(payload_size) - kPreLabel;
        const size_t want = std::min<size_t>(kMaxLabel, avail);
        if (auto nm = r.bytes(label_off, want)) {
            std::string name(reinterpret_cast<const char*>(nm->data()), nm->size());
            auto nul = name.find('\0');
            if (nul != std::string::npos) name = name.substr(0, nul);
            bool printable = !name.empty() &&
                              std::all_of(name.begin(), name.end(),
                                          [](unsigned char c) { return c >= 0x20 && c < 0x7f; });
            if (printable) ctx.out.label = name;
        }
    }

    // Check the constant 8-byte tag at payload offset 0x10.
    bool tag_ok = false;
    if (payload_size >= kPreLabel) {
        const size_t tag_off = base + header_length + 16;
        if (auto tag = r.bytes(tag_off, 8))
            tag_ok = (std::memcmp(tag->data(), kExpectedTag, 8) == 0);
    }

    if (total == r.size() - base && tag_ok)
        ctx.out.set_confidence(Confidence::Verified,
                               "header+payload+trailer spans file exactly; tag matches");
    else if (total == r.size() - base)
        ctx.out.set_confidence(Confidence::Consistent,
                               "header+payload+trailer spans file exactly; tag mismatch");
    else
        ctx.out.set_confidence(Confidence::Structural,
                               "header+payload+trailer fits within file");
    return true;
}

}  // namespace ft

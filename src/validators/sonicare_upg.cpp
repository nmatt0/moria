// sonicare_upg.cpp — Philips Sonicare ".upg" firmware container validator.
//
// Container layout (all integers little-endian):
//   0x00  bytes[4]  magic            FC 55 50 48
//   0x04  u32       reserved         constant 0xFFFFFFFF (enforced by constraint)
//   0x08  u32       payload_size
//   0x0C  u16       format_version   constant 1 (enforced by constraint)
//   0x0E  u16       header_length    constant 0x38 (enforced by constraint)
//   0x10  ...       unidentified, fills out header_length bytes
//   header_length            payload_size bytes of payload
//   header_length+payload_size   16-byte trailer, unidentified
//
// The payload opens with a 236-byte plaintext header. Confirmed identical in
// shape across six real samples:
//   +0x00   16 B  opaque per-file value (nonce or digest, undetermined)
//   +0x10    8 B  constant tag (kExpectedTag), the format's only self-check
//   +0x18   64 B  NUL-padded ASCII device/product name  <- ctx.out.label
//   +0x58   64 B  NUL-padded ASCII
//   +0x98   64 B  NUL-padded ASCII
//   +0xd8   12 B  u32 flag, u32 (unidentified), char[8] component name, u32
//   +0xec   ...   encrypted firmware body (key on the MCU)
// The TOML's soft constraint rejects payload_size < 0xec, so by the time this
// runs the whole plaintext header is present.
//
// Tiering follows `otra` and `vbf`: the format's own internal check drives the
// top tier and landing on EOF is secondary, because a container read out of an
// APK's assets or a flash dump is embedded by definition and can never end the
// file. Spanning to EOF with a matching tag is `verified`; either signal alone
// is `consistent`; neither is `structural`.
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
constexpr size_t kLabelField = 64;  // the field's real width: payload 0x18..0x57
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

    // Label: a fixed 64-byte NUL-padded ASCII field, clamped to stay inside the
    // payload so a short one can't source it from the trailer or past the
    // container. A window with no NUL in it is not this field, so reject rather
    // than report 64 characters of whatever happened to be printable.
    if (payload_size > kPreLabel) {
        const size_t label_off = base + header_length + kPreLabel;
        const size_t avail = static_cast<size_t>(payload_size) - kPreLabel;
        const size_t want = std::min<size_t>(kLabelField, avail);
        if (auto nm = r.bytes(label_off, want)) {
            std::string name(reinterpret_cast<const char*>(nm->data()), nm->size());
            const auto nul = name.find('\0');
            if (nul != std::string::npos) {
                name = name.substr(0, nul);
                const bool printable =
                    !name.empty() && std::all_of(name.begin(), name.end(), [](unsigned char c) {
                        return c >= 0x20 && c < 0x7f;
                    });
                if (printable) ctx.out.label = name;
            }
        }
    }

    // The constant 8-byte tag at payload offset 0x10.
    bool tag_ok = false;
    if (payload_size >= kPreLabel) {
        const size_t tag_off = base + header_length + 16;
        if (auto tag = r.bytes(tag_off, 8))
            tag_ok = (std::memcmp(tag->data(), kExpectedTag, 8) == 0);
    }
    const bool exact_eof = (total == r.size() - base);

    if (exact_eof && tag_ok)
        ctx.out.set_confidence(Confidence::Verified,
                               "header+payload+trailer spans file exactly; tag matches");
    else if (tag_ok)
        ctx.out.set_confidence(Confidence::Consistent,
                               "tag matches; header+payload+trailer fits within file");
    else if (exact_eof)
        ctx.out.set_confidence(Confidence::Consistent,
                               "header+payload+trailer spans file exactly; tag mismatch");
    else
        ctx.out.set_confidence(Confidence::Structural,
                               "header+payload+trailer fits within file");
    return true;
}

}  // namespace ft

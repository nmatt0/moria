// upg.cpp — ".upg" firmware container validator.
//
// Layout (all integers little-endian):
//   0x00  bytes[4]  magic            FC 55 50 48
//   0x04  u32       reserved         observed constant 0xFFFFFFFF
//   0x08  u32       payload_size
//   0x0C  u16       format_version   observed constant 1
//   0x0E  u16       header_length    observed constant 0x38 (56)
//   0x10  ...       unidentified, fills out header_length bytes
//   header_length            payload_size bytes of payload
//   header_length+payload_size   16-byte trailer, unidentified
// header_length + payload_size + 16 landing exactly on EOF is the strongest
// signal available (no known reference implementation to cross-check against).
// The payload's own first 16 bytes are opaque and differ per sample (nonce or
// digest, undetermined); a constant 8-byte tag (01 00 14 01 02 00 00 00 in
// every sample seen, meaning unknown) follows, then a short NUL-padded ASCII
// label (component/device name) at payload offset 0x18.
#include "validators/upg.hpp"

#include <algorithm>
#include <string>

namespace ft {

namespace {
uint64_t field(const FieldMap& f, const char* k) {
    auto it = f.find(k);
    return it == f.end() ? 0 : it->second;
}

// Payload bytes before the label: 16 opaque (varies per sample) + an 8-byte
// tag observed constant (01 00 14 01 02 00 00 00) across every real sample.
constexpr size_t kPreLabel = 24;
constexpr size_t kTrailer = 16;
constexpr size_t kMaxLabel = 64;
}  // namespace

bool validate_upg(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;

    const uint64_t header_length = field(ctx.fields, "header_length");  // constraint already == 0x38
    const uint64_t payload_size = field(ctx.fields, "payload_size");
    const uint64_t total = header_length + payload_size + kTrailer;

    if (base > r.size() || total > r.size() - base) return false;  // doesn't fit: not a real match
    ctx.out.size = total;

    const size_t label_off = base + header_length + kPreLabel;
    if (label_off < r.size()) {
        const size_t want = std::min<size_t>(kMaxLabel, r.size() - label_off);
        if (auto nm = r.bytes(label_off, want)) {
            std::string name(reinterpret_cast<const char*>(nm->data()), nm->size());
            name = name.substr(0, name.find('\0'));
            bool printable = !name.empty() &&
                              std::all_of(name.begin(), name.end(),
                                          [](unsigned char c) { return c >= 0x20 && c < 0x7f; });
            if (printable) ctx.out.label = name;  // embedded component/device name, e.g. a boot-stage name
        }
    }

    if (total == r.size() - base)
        ctx.out.set_confidence(Confidence::Verified, "header+payload+trailer spans file exactly");
    else
        ctx.out.set_confidence(Confidence::Structural, "header+payload+trailer fits within file");
    return true;
}

}  // namespace ft

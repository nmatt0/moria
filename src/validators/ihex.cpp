// ihex.cpp — Intel HEX validator (anchored at offset 0; text format).
// Record: ':' BB AAAA TT [DD..] CC, all ASCII hex. Checksum: two's complement
// of the sum of every byte from BB through the last data byte.
#include "validators/ihex.hpp"

#include <optional>

namespace ft {

namespace {
std::optional<uint32_t> hex_byte(const Reader& r, size_t at) {
    uint32_t v = 0;
    for (size_t i = 0; i < 2; ++i) {
        auto b = r.bytes(at + i, 1);
        if (!b) return std::nullopt;
        uint8_t c = (*b)[0];
        if (c >= '0' && c <= '9') v = v * 16 + (c - '0');
        else if (c >= 'a' && c <= 'f') v = v * 16 + (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = v * 16 + (c - 'A' + 10);
        else return std::nullopt;
    }
    return v;
}
}  // namespace

bool validate_ihex(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;  // ':' position (0)

    auto byte_count = hex_byte(r, off + 1);
    auto addr_hi = hex_byte(r, off + 3);
    auto addr_lo = hex_byte(r, off + 5);
    auto rectype = hex_byte(r, off + 7);
    if (!byte_count || !addr_hi || !addr_lo || !rectype) return false;
    if (*rectype > 5) return false;

    uint32_t sum = *byte_count + *addr_hi + *addr_lo + *rectype;
    size_t pos = off + 9;
    for (uint32_t i = 0; i < *byte_count; ++i) {
        auto d = hex_byte(r, pos);
        if (!d) return false;
        sum += *d;
        pos += 2;
    }
    auto checksum = hex_byte(r, pos);
    if (checksum && ((sum + *checksum) & 0xFF) == 0) {
        ctx.out.set_confidence(Confidence::Consistent, "Intel HEX record and checksum are valid");
        return true;
    }

    // Fallback: a leading ':' followed by a long run of hex then a line break is
    // an ASCII-hex record even if it isn't standard Intel HEX (e.g. Tuya .H16,
    // which uses wider fields). Report at structural tier.
    size_t hexrun = 0;
    for (size_t i = off + 1; ; ++i) {
        auto b = r.bytes(i, 1);
        if (!b) break;
        uint8_t ch = (*b)[0];
        bool is_hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        if (is_hex) { ++hexrun; continue; }
        if ((ch == '\r' || ch == '\n') && hexrun >= 8) {
            ctx.out.set_confidence(Confidence::Structural,
                                   "plain-text hex records in a non-standard form");
            return true;
        }
        break;
    }
    return false;
}

}  // namespace ft

// tar.cpp — POSIX ustar archive validator. See tar.hpp.
// A ustar header is 512 bytes: name[100], mode/uid/gid, size[12] (octal) @124,
// chksum[8] (octal) @148, "ustar" magic @257. The archive ends at a zero block.
// We walk members to compute the total span and validate the header checksum so a
// coincidental "ustar" in binary data (and each interior member header) does not
// spawn its own extraction.
#include "validators/tar.hpp"

#include <cstdint>
#include <cstring>
#include <optional>

namespace ft {

namespace {

uint64_t roundup512(uint64_t x) { return (x + 511) & ~uint64_t(511); }

// Parse an octal field of up to `n` bytes: skip leading spaces/NULs, take octal
// digits until a space/NUL/end. nullopt if a non-octal, non-terminator byte
// appears before any digit's terminator.
std::optional<uint64_t> octal_field(const Reader& r, size_t at, size_t n) {
    auto b = r.bytes(at, n);
    if (!b) return std::nullopt;
    uint64_t v = 0;
    size_t i = 0;
    while (i < n && ((*b)[i] == ' ' || (*b)[i] == '\0')) ++i;  // leading pad
    bool any = false;
    for (; i < n; ++i) {
        uint8_t c = (*b)[i];
        if (c == ' ' || c == '\0') break;  // trailing terminator
        if (c < '0' || c > '7') return std::nullopt;
        v = v * 8 + (c - '0');
        any = true;
    }
    if (!any) return std::nullopt;
    return v;
}

}  // namespace

bool validate_tar(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;  // block start; "ustar" magic sits at base+257
    const size_t limit = r.size();

    size_t pos = base;
    uint64_t members = 0;
    const uint64_t kMaxMembers = 200000;  // guard against pathological input
    while (pos + 512 <= limit && members < kMaxMembers) {
        auto blk = r.bytes(pos, 512);
        if (!blk) break;
        // End-of-archive: an all-zero block.
        bool zero = true;
        for (uint8_t c : *blk)
            if (c) { zero = false; break; }
        if (zero) {
            pos += 512;  // consume the terminator block
            break;
        }
        // ustar magic must be present at each member header.
        if (std::memcmp(blk->data() + 257, "ustar", 5) != 0) break;
        // Validate the stored octal checksum against the computed header sum
        // (the 8-byte checksum field itself counted as spaces).
        auto stored = octal_field(r, pos + 148, 8);
        if (!stored) break;
        uint32_t sum = 0;
        for (size_t i = 0; i < 512; ++i)
            sum += (i >= 148 && i < 156) ? uint8_t(' ') : (*blk)[i];
        if (sum != *stored) break;
        auto sz = octal_field(r, pos + 124, 12);
        if (!sz) break;
        pos += 512 + roundup512(*sz);
        ++members;
    }

    if (members == 0) return false;  // no valid header -> reject (stray "ustar")
    size_t span = (pos <= limit ? pos : limit) - base;
    if (span > ctx.out.size) ctx.out.size = span;
    ctx.out.set_confidence(Confidence::Consistent, "tar file list and total size checked");
    return true;
}

}  // namespace ft

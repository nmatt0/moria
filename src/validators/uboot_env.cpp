// uboot_env.cpp — U-Boot environment refinement validator. See uboot_env.hpp.
//
// On-disk layout (env/):
//   single:     u32 crc; char data[ENV_SIZE-4];
//   redundant:  u32 crc; u8 flags; char data[ENV_SIZE-5];
// `data` is a NUL-separated `key=value` list ending in an empty entry, then
// padding to the fixed ENV_SIZE. crc is crc32(0, data, ENV_SIZE-hlen) (the
// standard zlib CRC-32, == crc32_ieee here) over the whole data array including
// padding, so a verify needs the exact env size — we try the common flash
// region sizes and the tightly-dumped length.
//
// The signature anchors on a NUL-prefixed common assignment (`\0bootcmd=`, ...),
// which can only land at a true entry boundary. From there we walk back to the
// first entry, forward to the terminator, and CRC-verify.
#include "validators/uboot_env.hpp"

#include <cstdint>
#include <span>
#include <string>

#include "crc32.hpp"

namespace ft {

namespace {

constexpr size_t kMaxEnv = size_t(2) << 20;  // 2 MiB scan/window cap
constexpr size_t kMinEntries = 4;            // structural false-positive guard

inline bool key_char(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '_';
}
inline bool val_char(uint8_t c) {
    return (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r';
}

// [start, end) is a well-formed `key=value`: a nonempty key of key-chars, a '=',
// then zero or more value chars. `end` is the index of the terminating '\0'.
bool entry_ok(std::span<const uint8_t> d, size_t start, size_t end) {
    if (end <= start) return false;  // empty entry (the list terminator)
    size_t i = start;
    if (!key_char(d[i])) return false;
    while (i < end && key_char(d[i])) ++i;
    if (i >= end || d[i] != '=') return false;
    for (++i; i < end; ++i)
        if (!val_char(d[i])) return false;
    return true;
}

}  // namespace

bool validate_uboot_env(ValidatorCtx& ctx) {
    std::span<const uint8_t> d = ctx.reader.data();
    const size_t n = d.size();
    const size_t anchor = ctx.offset;  // the '\0' separating the anchor entry
    if (anchor >= n || d[anchor] != 0x00) return false;

    // Walk backward to the first entry's start. `sep` is always a separator NUL;
    // step back one entry at a time until the byte before an entry is not a
    // separator (the block header) or the candidate entry is malformed.
    size_t body_start = anchor + 1;
    size_t sep = anchor;
    const size_t back_limit = anchor > kMaxEnv ? anchor - kMaxEnv : 0;
    while (sep > back_limit) {
        size_t i = sep;
        while (i > back_limit) {
            uint8_t c = d[i - 1];
            if (c == 0x00 || !val_char(c)) break;  // previous separator / header boundary
            --i;
        }
        if (!entry_ok(d, i, sep)) break;  // reached the header (or malformed) -> stop
        body_start = i;
        if (i == 0 || d[i - 1] != 0x00) break;  // header boundary before this entry
        sep = i - 1;                             // another separator: keep walking back
    }

    // Walk forward to the empty-entry terminator, validating each entry.
    size_t entries = 0;
    size_t p = body_start;
    bool terminated = false;
    const size_t fwd_limit = body_start + kMaxEnv < n ? body_start + kMaxEnv : n;
    while (p < fwd_limit) {
        if (d[p] == 0x00) { terminated = true; break; }  // empty entry = end of list
        size_t s = p;
        while (p < fwd_limit && d[p] != 0x00) ++p;
        if (p >= fwd_limit || !entry_ok(d, s, p)) break;
        ++entries;
        ++p;  // step over the separator
    }
    if (!terminated || entries < kMinEntries) return false;
    const size_t body_end = p;  // index of the terminating '\0'

    // CRC32 verification over candidate env sizes, for both header layouts. The
    // backward walk can absorb a printable header byte into the first key (a CRC
    // byte that happens to be [A-Za-z0-9_]), so the real data start is at or a few
    // bytes past `body_start`; search a small window and let the CRC pin it exactly.
    static const size_t kSizes[] = {0x1000,  0x2000,  0x4000,  0x8000,   0x10000,
                                    0x20000, 0x40000, 0x80000, 0x100000, 0x200000};
    bool verified = false;
    size_t hstart = 0, hlen = 4, total = 0;
    for (size_t ds = body_start; ds <= body_start + 5 && ds <= body_end && !verified; ++ds) {
        for (size_t hl : {size_t(4), size_t(5)}) {
            if (ds < hl) continue;
            const size_t hs = ds - hl;
            auto stored = ctx.reader.at<uint32_t>(hs, Endian::Little);
            if (!stored) continue;
            auto try_total = [&](size_t t) -> bool {
                if (t <= hl || hs > n || t > n - hs) return false;  // runs past EOF
                auto body = ctx.reader.bytes(ds, t - hl);
                if (!body || crc32_ieee(*body) != *stored) return false;
                hstart = hs;
                hlen = hl;
                total = t;
                verified = true;
                return true;
            };
            for (size_t s : kSizes)
                if (try_total(s)) break;
            if (!verified) try_total((body_end + 1 - ds) + hl);  // tightly-dumped, no padding
            if (verified) break;
        }
    }

    if (verified) {
        ctx.out.offset = hstart;
        ctx.out.size = total;
        ctx.out.label = (hlen == 5) ? "redundant" : "";
        ctx.out.set_confidence(Confidence::Verified,
                               "CRC32 header verified (" + std::to_string(entries) +
                                   " vars, env size " + std::to_string(total) + ")");
        return true;
    }

    // Structural: a clean key=value list, header CRC not confirmed. Assume the
    // single 4-byte header and size the finding to the used bytes only.
    const size_t used = (body_end + 1) - body_start;  // through the terminating NUL
    if (body_start < 4) {
        ctx.out.offset = body_start;
        ctx.out.size = used;
    } else {
        ctx.out.offset = body_start - 4;
        ctx.out.size = used + 4;
    }
    ctx.out.set_confidence(Confidence::Structural,
                           "U-Boot key=value list (" + std::to_string(entries) +
                               " vars, CRC unverified)");
    ctx.out.diagnostics.push_back(
        {"info", "uboot-env-crc-unverified",
         "header CRC32 not matched to a known env size; block extent is approximate"});
    return true;
}

}  // namespace ft

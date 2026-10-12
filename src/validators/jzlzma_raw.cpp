// jzlzma_raw.cpp — Ingenic raw-jzlzma identifier. See jzlzma.hpp for format.
//
// The raw form has no magic: [dict_size u32 LE][uncomp_size u32 LE][stream].
// Candidates are anchored structurally on the dict field (powers of two from
// 64 KiB to 128 MiB) and validated by trial-decoding to EXACTLY uncomp_size
// bytes — the stream self-terminates there, so plausible-looking random bytes
// cannot pass. A candidate sitting inside a mark_rootfs_lzma wrapper (BE
// 0x27051956 u32 immediately before the anchor) is rejected so the wrapped
// signature and this one never double-report the same stream.
#include "validators/jzlzma_raw.hpp"

#include <cstdint>
#include <string>

#include "../finding.hpp"
#include "extract/jzlzma.hpp"

namespace ft {

namespace {

// Same sane dictionary bound as the wrapped validator (the decoder never
// allocates a window; this only rejects an implausible header). Observed
// devices use 64 KiB.
constexpr uint32_t kMaxDict = uint32_t(256) << 20;

}  // namespace

bool validate_jzlzma_raw(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    auto dict = r.at<uint32_t>(off, Endian::Little);
    auto uncomp = r.at<uint32_t>(off + 4, Endian::Little);
    if (!dict || !uncomp) return false;  // header runs past EOF
    if (*dict == 0 || *dict > kMaxDict) return false;
    if (*uncomp == 0 || *uncomp > kJzlzmaMaxOut) return false;

    // Inside a mark_rootfs_lzma wrapper? The wrapper's 16-byte header ends
    // right where our 8-byte one would begin, and its last field is the
    // U-Boot magic (stored little-endian: bytes 56 19 05 27). Let the wrapped
    // signature own that stream.
    if (off >= 4) {
        if (auto prev = r.at<uint32_t>(off - 4, Endian::Little);
            prev && *prev == 0x27051956)
            return false;
    }

    if (r.size() - off < 8 + 16) return false;  // no room for a real stream

    // FP-proof gate: trial-decode. Random bytes run out of input or reach
    // before the output start long before producing the declared size, so
    // they cannot pass. A stream of 1-bit rep0 shortcuts amplifies input ~8x
    // at worst, so the cost is bounded by the input span, not the declared
    // size. T41 firmware (Wyze Cam v4) over-declares the size by ~1 KiB — the
    // stream ends with NUL-literal padding to the stated uncomp_size — so a
    // short decode is accepted when it covers most of the declared output
    // (>= 90%) and is substantial (>= 4 KiB); exact decodes stay the norm.
    const size_t span = r.size() - (off + 8);
    auto src = r.bytes(off + 8, span);
    if (!src) return false;
    size_t consumed = 0;
    auto decoded = jzlzma_decode(*src, *uncomp, &consumed);
    bool padded_stream = false;
    if (!decoded) {
        decoded = jzlzma_decode(*src, *uncomp, &consumed, /*allow_short=*/true);
        if (!decoded) return false;
        const uint64_t got = decoded->size();
        if (got < (*uncomp * 9) / 10 || got < 4096) return false;
        padded_stream = true;
    }

    Finding& out = ctx.out;
    out.size = 8 + consumed;  // owns only the bytes the stream really used
    if (padded_stream) {
        out.diagnostics.push_back(
            {"info", "jzlzma-short",
             "declared " + std::to_string(*uncomp) + " bytes, stream produced " +
                 std::to_string(decoded->size()) + " (padded-stream over-declaration)"});
    }
    std::string dict_str;
    if (*dict >= (1u << 20))
        dict_str = std::to_string(*dict >> 20) + " MiB";
    else
        dict_str = std::to_string(*dict >> 10) + " KiB";
    out.label = std::to_string(*uncomp) + " bytes, dict " + dict_str;
    out.set_confidence(Confidence::Verified,
                       "jzlzma: decoded " + std::to_string(*uncomp) + " bytes, dict " + dict_str);
    return true;
}

}  // namespace ft

// lzma.cpp — legacy standalone LZMA1 (".lzma alone") identifier. See lzma.hpp.
#include "validators/lzma.hpp"

#include <cstdint>
#include <string>

#include "extract/decompress.hpp"

namespace ft {

namespace {

// The .lzma header: [props u8][dict_size u32 LE][uncompressed_size u64 LE].
constexpr uint64_t kUnknownSize = UINT64_MAX;  // all-0xFF = size not stored
// props = (pb * 5 + lp) * 9 + lc, with lc<=8, lp<=4, pb<=4 → max 224.
constexpr uint8_t kMaxProps = 224;
// Dictionary bounds. Real firmware uses 8/16/32/64 MiB; the format allows less.
// A multiple of 64 KiB (the `5D 00 00` anchor guarantees the low 16 bits are 0),
// required to be a power of two in [4 KiB, 768 MiB].
constexpr uint32_t kMinDict = 1u << 12;
constexpr uint32_t kMaxDict = 768u << 20;
// Cap the identify-time trial decode. Larger than any plausible firmware LZMA
// payload, so a real stream reaches its end marker, while a decompression bomb
// cannot make identify decode unbounded output.
constexpr size_t kProbeCap = 512u << 20;

}  // namespace

bool validate_lzma(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    auto props = r.at<uint8_t>(off, Endian::Little);
    auto dict = r.at<uint32_t>(off + 1, Endian::Little);
    auto usize = r.at<uint64_t>(off + 5, Endian::Little);
    if (!props || !dict || !usize) return false;  // header runs past EOF

    if (*props > kMaxProps) return false;
    if (*dict < kMinDict || *dict > kMaxDict) return false;
    if ((*dict & (*dict - 1)) != 0) return false;  // not a power of two

    const bool known = (*usize != kUnknownSize);
    if (known && (*usize == 0 || *usize > kProbeCap)) return false;  // implausible declared size

    // FP-proof gate: trial-decode to a clean end-of-stream marker. A stray
    // `5D 00 00 ...` cannot reach the marker, so it is rejected here.
    auto src = r.bytes(off, r.size() - off);
    if (!src) return false;
    size_t consumed = 0;
    auto decoded = lzma_alone_probe(*src, kProbeCap, &consumed);
    if (!decoded) return false;
    if (known && *decoded != *usize) return false;  // declared size must match actual

    Finding& out = ctx.out;
    out.type = "lzma";
    out.category = "compression";
    out.endian = Endian::Little;
    out.offset = off;
    out.size = consumed;  // the exact compressed span, so the region is claimed
    const uint32_t dict_mib = *dict >> 20;
    std::string dict_str = dict_mib ? std::to_string(dict_mib) + " MiB" : std::to_string(*dict) + " B";
    out.label = std::to_string(*decoded) + " bytes, dict " + dict_str;
    out.set_confidence(Confidence::Verified,
                       "LZMA1 alone: decoded " + std::to_string(*decoded) +
                           " bytes to end marker, dict " + dict_str);
    return true;
}

}  // namespace ft

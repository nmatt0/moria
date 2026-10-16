// jzlzma.cpp — Ingenic jzlzma identifier. See jzlzma.hpp.
#include "validators/jzlzma.hpp"

#include <cstdint>
#include <string>

#include "extract/jzlzma.hpp"

namespace ft {

namespace {

// Sane dictionary bound (the decoder never allocates a window; this only
// rejects an implausible header). Observed devices use 64 KiB.
constexpr uint32_t kMaxDict = uint32_t(256) << 20;

}  // namespace

bool validate_jzlzma(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    // The struct constraints already ran; re-read the fields the decode needs.
    auto payload_size = r.at<uint32_t>(off, Endian::Little);
    auto dict = r.at<uint32_t>(off + 8, Endian::Little);
    auto uncomp = r.at<uint32_t>(off + 12, Endian::Little);
    if (!payload_size || !dict || !uncomp) return false;  // header runs past EOF
    if (*payload_size == 0) return false;
    if (*dict == 0 || *dict > kMaxDict) return false;
    if (*uncomp == 0 || *uncomp > kJzlzmaMaxOut) return false;
    if (16 + static_cast<uint64_t>(*payload_size) > r.size() - off) return false;  // past EOF

    // FP-proof gate: a jzlzma stream self-terminates at exactly its declared
    // uncompressed size. Random bytes after a `56 19 05 27` hit run out of
    // input or reach before the output start long before producing that many
    // bytes, so they are rejected here.
    auto src = r.bytes(off + 16, *payload_size);
    if (!src) return false;
    auto decoded = jzlzma_decode(*src, *uncomp);
    if (!decoded) return false;

    Finding& out = ctx.out;
    out.size = 16 + static_cast<size_t>(*payload_size);
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

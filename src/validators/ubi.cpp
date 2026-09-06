// ubi.cpp — UBI/UBIFS header CRC verification.
#include "validators/ubi.hpp"
#include "crc32.hpp"

namespace ft {

bool validate_ubi(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;
    auto hdr = r.bytes(off, 60);
    auto stored = r.at<uint32_t>(off + 60, Endian::Big);  // hdr_crc is big-endian
    if (!hdr || !stored) return true;                     // keep structural default
    if (crc32_ubi(*hdr) == *stored)
        ctx.out.set_confidence(Confidence::Verified, "UBI header CRC ok");
    return true;
}

bool validate_ubifs(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;
    auto crc = r.at<uint32_t>(off + 4, Endian::Little);
    auto len = r.at<uint32_t>(off + 16, Endian::Little);
    if (!crc || !len || *len < 8) return true;
    const uint64_t avail = r.size() - off;
    if (*len > avail) return true;
    auto body = r.bytes(off + 8, *len - 8);  // crc covers node[8..len]
    if (!body) return true;
    if (crc32_ubi(*body) == *crc)
        ctx.out.set_confidence(Confidence::Verified, "UBIFS node CRC ok");
    return true;
}

}  // namespace ft

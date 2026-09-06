// jffs2.cpp — verify the first node's header CRC (JFFS2 crc32 variant, init 0).
#include "validators/jffs2.hpp"
#include "crc32.hpp"

namespace ft {

bool validate_jffs2(ValidatorCtx& ctx) {
    auto it = ctx.fields.find("hdr_crc");
    if (it == ctx.fields.end()) return true;  // no field -> keep structural default
    auto hdr = ctx.reader.bytes(ctx.offset, 8);
    if (!hdr) return true;
    if (crc32_jffs2(*hdr) == static_cast<uint32_t>(it->second))
        ctx.out.set_confidence(Confidence::Verified, "node header CRC ok");
    return true;
}

}  // namespace ft

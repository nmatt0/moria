// png.cpp — PNG size via chunk walk (IHDR ... IEND), with per-chunk CRC-32. #58.
#include "validators/png.hpp"

#include <cstdint>

#include "crc32.hpp"

namespace ft {

bool validate_png(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;
    const size_t limit = r.size();

    // The magic already matched the 8-byte signature plus the IHDR length+type,
    // so the first chunk starts at base+8. A chunk is length(4 BE) | type(4) |
    // data[length] | crc(4); the CRC covers type+data. Walk to IEND.
    size_t pos = base + 8;
    bool all_crc_ok = true;
    for (int guard = 0; guard < 100000; ++guard) {
        auto len = r.at<uint32_t>(pos, Endian::Big);
        auto type = r.bytes(pos + 4, 4);
        if (!len || !type) break;             // chunk header runs off EOF
        if (*len > limit - (pos + 8)) break;  // data runs off EOF
        const size_t crc_pos = pos + 8 + *len;
        auto crc = r.at<uint32_t>(crc_pos, Endian::Big);
        if (!crc) break;                      // crc runs off EOF
        auto covered = r.bytes(pos + 4, 4 + *len);  // type + data
        if (covered && crc32_ieee(*covered) != *crc) all_crc_ok = false;

        const auto& t = *type;
        const bool is_iend = t[0] == 'I' && t[1] == 'E' && t[2] == 'N' && t[3] == 'D';
        const size_t chunk_end = crc_pos + 4;
        if (is_iend) {
            ctx.out.size = chunk_end - base;
            if (all_crc_ok)
                ctx.out.set_confidence(Confidence::Verified,
                                       "PNG chunks walked to IEND, every chunk CRC-32 verified");
            else
                ctx.out.set_confidence(Confidence::Consistent, "PNG chunks walked to IEND");
            return true;
        }
        pos = chunk_end;
    }
    // No IEND reached (truncated or malformed): keep the decisive magic-tier
    // finding and let size inference fall back. Do not reject.
    return true;
}

}  // namespace ft

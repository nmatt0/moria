// gif.cpp — GIF size via block walk (header ... 0x3B trailer). #58.
#include "validators/gif.hpp"

#include <cstdint>
#include <optional>

namespace ft {

namespace {

// Skip a GIF sub-block chain: [size u8][size bytes]... ended by a 0x00 size.
// Returns the offset just past the terminator, or nullopt on EOF / overrun.
std::optional<size_t> skip_subblocks(const Reader& r, size_t pos) {
    const size_t limit = r.size();
    for (int guard = 0; guard < 100000; ++guard) {
        auto sz = r.bytes(pos, 1);
        if (!sz) return std::nullopt;
        uint8_t n = (*sz)[0];
        pos += 1;
        if (n == 0) return pos;              // block terminator
        if (n > limit - pos) return std::nullopt;  // data runs off EOF
        pos += n;
    }
    return std::nullopt;
}

}  // namespace

bool validate_gif(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;

    // Header (6 bytes) + logical screen descriptor (7 bytes). The packed byte at
    // base+10 flags a global color table and encodes its size.
    auto packed = r.bytes(base + 10, 1);
    if (!packed) return true;                // too short to walk; keep magic tier
    size_t pos = base + 13;
    if ((*packed)[0] & 0x80) {
        int n = (*packed)[0] & 0x07;
        pos += 3u << (n + 1);                // global color table: 3 * 2^(n+1) bytes
    }

    // Validity gate (also FP rejection). The 6-byte GIF8[79]a magic alone matches
    // stray occurrences in binary/compressed data. After the header + GCT, a real
    // GIF's data stream must begin with a block introducer: image descriptor
    // (0x2C), extension (0x21), or the trailer (0x3B). Anything else proves this
    // is not a GIF, so reject the finding. A truncated-but-real GIF still has a
    // valid first introducer, so it survives this gate and falls through below.
    auto first = r.bytes(pos, 1);
    if (!first) return true;                 // header present but body past EOF: keep magic tier
    if ((*first)[0] != 0x2C && (*first)[0] != 0x21 && (*first)[0] != 0x3B) return false;

    for (int guard = 0; guard < 1000000; ++guard) {
        auto intro = r.bytes(pos, 1);
        if (!intro) break;                   // ran off EOF before the trailer
        uint8_t b = (*intro)[0];
        if (b == 0x3B) {                     // trailer
            ctx.out.size = (pos - base) + 1;
            ctx.out.set_confidence(Confidence::Consistent,
                                   "GIF blocks walked to trailer, size computed");
            return true;
        }
        if (b == 0x2C) {                     // image descriptor
            // 0x2C + left,top,width,height (u16 each) + packed(u8) = 10 bytes;
            // the image-descriptor packed byte sits at pos+9.
            auto lp = r.bytes(pos + 9, 1);
            if (!lp) break;
            size_t p = pos + 10;
            if ((*lp)[0] & 0x80) {
                int n = (*lp)[0] & 0x07;
                p += 3u << (n + 1);          // local color table
            }
            auto lzw = r.bytes(p, 1);        // LZW minimum code size
            if (!lzw) break;
            auto nxt = skip_subblocks(r, p + 1);  // image-data sub-block chain
            if (!nxt) break;
            pos = *nxt;
        } else if (b == 0x21) {              // extension: label byte, then sub-blocks
            auto nxt = skip_subblocks(r, pos + 2);
            if (!nxt) break;
            pos = *nxt;
        } else {
            break;                           // unknown block: malformed, stop
        }
    }
    // No trailer reached: keep the decisive magic-tier finding and let size
    // inference fall back. Do not reject.
    return true;
}

}  // namespace ft

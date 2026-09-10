// jpeg.cpp — JPEG size via marker-segment walk (SOI ... EOI).
#include "validators/jpeg.hpp"

namespace ft {

// A start-of-frame marker (real image data). SOF0-15, excluding DHT(C4)/JPG(C8)/
// DAC(CC). Seeing one is strong proof this is a JPEG, not a stray FF D8 FF.
static bool is_sof(uint8_t m) {
    return m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC;
}

bool validate_jpeg(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;
    size_t pos = base + 2;  // after SOI (FF D8)
    const size_t limit = r.size();
    bool saw_sof = false;  // a real frame header -> accept; without it, reject

    // The magic (FF D8 FF) also occurs inside compressed/random data. Accept only
    // when the marker walk actually reaches a frame header (SOF) or the end of
    // image (EOI); if it bails before proving structure, reject the finding.
    for (int guard = 0; guard < 100000 && pos + 1 < limit; ++guard) {
        auto b0 = r.bytes(pos, 1);
        if (!b0 || (*b0)[0] != 0xFF) return saw_sof;  // marker expected here
        // consume fill bytes (0xFF ...)
        size_t m = pos + 1;
        uint8_t marker = 0;
        while (m < limit) {
            auto mb = r.bytes(m, 1);
            if (!mb) return saw_sof;
            marker = (*mb)[0];
            if (marker != 0xFF) break;
            ++m;
        }
        if (marker == 0xD9) {  // EOI
            ctx.out.size = (m + 1) - base;
            ctx.out.set_confidence(Confidence::Consistent,
                                   "JPEG start and end found and size checked");
            return true;
        }
        // SOI/RST as the next marker is invalid inside a well-formed stream.
        if (marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01) return saw_sof;
        // segment with a 2-byte big-endian length
        auto len = r.at<uint16_t>(m + 1, Endian::Big);
        if (!len || *len < 2) return saw_sof;
        size_t seg_end = m + 1 + *len;
        if (seg_end > limit) return saw_sof;  // segment runs off the end
        if (is_sof(marker)) {
            // Validate the frame header, not just the marker: precision is 8 or 12,
            // dimensions are non-zero, component count is 1/3/4, and the segment
            // length matches. This rejects a stray FF D8 FF C0 in binary data.
            auto prec = r.bytes(m + 3, 1);
            auto h = r.at<uint16_t>(m + 4, Endian::Big);
            auto w = r.at<uint16_t>(m + 6, Endian::Big);
            auto nc = r.bytes(m + 8, 1);
            if (!prec || !h || !w || !nc) return saw_sof;
            uint8_t p = (*prec)[0], comps = (*nc)[0];
            if ((p != 8 && p != 12) || *h == 0 || *w == 0 ||
                (comps != 1 && comps != 3 && comps != 4) ||
                *len != 8 + static_cast<uint16_t>(comps) * 3) {
                return saw_sof;  // not a real frame header
            }
            saw_sof = true;
        }
        if (marker == 0xDA) {  // SOS: entropy-coded data follows; scan to next real marker
            if (!saw_sof) return false;  // SOS before any frame header is not a JPEG
            size_t p = seg_end;
            while (p + 1 < limit) {
                auto fb = r.bytes(p, 1);
                if (!fb) return saw_sof;
                if ((*fb)[0] == 0xFF) {
                    auto nb = r.bytes(p + 1, 1);
                    if (!nb) return saw_sof;
                    uint8_t nm = (*nb)[0];
                    if (nm != 0x00 && !(nm >= 0xD0 && nm <= 0xD7)) { pos = p; break; }  // real marker
                }
                ++p;
            }
            if (p + 1 >= limit) return saw_sof;
            continue;
        }
        pos = seg_end;
    }
    return saw_sof;
}

}  // namespace ft

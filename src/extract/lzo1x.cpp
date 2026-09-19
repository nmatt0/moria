// lzo1x.cpp — internal LZO1X-safe decompressor. See lzo1x.hpp.
//
// Internal implementation of the public LZO1X decompression algorithm (no
// third-party code). Distances are computed as integers and validated
// against the amount already written before any source pointer is formed, so no
// out-of-bounds pointer arithmetic occurs even on a hostile stream. Match copies
// are byte-by-byte because source and destination may overlap by one byte.
#include "extract/lzo1x.hpp"

namespace ft {

bool lzo1x_decompress_safe(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap,
                           size_t* out_len, bool rle) {
    const uint8_t* ip = in;
    const uint8_t* const ip_end = in + in_len;
    uint8_t* op = out;
    uint8_t* const op_end = out + out_cap;
    size_t t;
    // LZO-RLE: a `0x11 <version>` header (present only in the rle variant) enables
    // the zero-run extension. Non-zero => RLE active.
    unsigned bitstream_version = 0;

    auto in_avail = [&](size_t n) { return static_cast<size_t>(ip_end - ip) >= n; };
    auto out_avail = [&](size_t n) { return static_cast<size_t>(op_end - op) >= n; };

    // Copy a match of `len` bytes at distance `off` (off>=1) behind op.
    auto copy_match = [&](size_t off, size_t len) -> bool {
        if (off == 0 || off > static_cast<size_t>(op - out)) return false;
        if (!out_avail(len)) return false;
        const uint8_t* m = op - off;
        while (len--) *op++ = *m++;
        return true;
    };
    // Copy `len` literal bytes from the input.
    auto copy_lit = [&](size_t len) -> bool {
        if (!out_avail(len) || !in_avail(len)) return false;
        while (len--) *op++ = *ip++;
        return true;
    };

    if (in_len == 0) { *out_len = 0; return true; }

    if (rle && in_len >= 5 && *ip == 17) {  // 0x11 <version> stream header
        bitstream_version = ip[1];
        ip += 2;
    }

    if (*ip > 17) {
        t = static_cast<size_t>(*ip++) - 17;
        if (t < 4) goto match_next;  // 1..3 leading literals, then a match
        if (!copy_lit(t)) return false;
        goto after_literal_run;
    }

    for (;;) {
        if (!in_avail(1)) return false;
        t = *ip++;
        if (t >= 16) goto match;
        // literal run: length t+3, or extended when t == 0
        if (t == 0) {
            if (!in_avail(1)) return false;
            while (*ip == 0) {
                t += 255;
                ++ip;
                if (!in_avail(1)) return false;
            }
            t += 15 + *ip++;
        }
        if (!copy_lit(t + 3)) return false;

    after_literal_run:
        // A command byte in [0,15] here (following a literal run) is a short M1
        // match; >=16 is a normal match.
        if (!in_avail(1)) return false;
        t = *ip++;
        if (t >= 16) goto match;
        {
            if (!in_avail(1)) return false;
            size_t off = 1 + 0x0800 + (t >> 2) + (static_cast<size_t>(*ip++) << 2);
            if (!copy_match(off, 3)) return false;
        }
        goto match_done;

    match:
        if (t >= 64) {  // M2: length 3..8, 11-bit distance
            if (!in_avail(1)) return false;
            size_t off = 1 + ((t >> 2) & 7) + (static_cast<size_t>(*ip++) << 3);
            if (!copy_match(off, (t >> 5) + 1)) return false;
        } else if (t >= 32) {  // M3: 5-bit (extended) length, 14-bit distance
            t &= 31;
            if (t == 0) {
                if (!in_avail(1)) return false;
                while (*ip == 0) { t += 255; ++ip; if (!in_avail(1)) return false; }
                t += 31 + *ip++;
            }
            if (!in_avail(2)) return false;
            size_t off = 1 + (static_cast<size_t>(ip[0]) >> 2) + (static_cast<size_t>(ip[1]) << 6);
            ip += 2;
            if (!copy_match(off, t + 2)) return false;
        } else if (t >= 16) {  // M4: 3-bit (extended) length, high-bit + 14-bit distance
            // LZO-RLE zero run: with RLE active, an M4 command of the form
            // t&0xf8==0x18 whose distance word has bits 2..15 all set encodes a
            // run of zeros (length from t's low bits + a third byte), then trailing
            // literals from the distance word's low 2 bits.
            if (bitstream_version && (t & 0xf8) == 0x18) {
                if (!in_avail(2)) return false;
                const size_t nx = static_cast<size_t>(ip[0]) | (static_cast<size_t>(ip[1]) << 8);
                if ((nx & 0xfffc) == 0xfffc) {
                    if (!in_avail(3)) return false;
                    size_t run = (t & 7) | (static_cast<size_t>(ip[2]) << 3);
                    run += 4;  // MIN_ZERO_RUN_LENGTH
                    if (!out_avail(run)) return false;
                    while (run--) *op++ = 0;
                    ip += 3;
                    t = nx & 3;  // trailing literals for the next instruction
                    if (t == 0) continue;  // state 0: next byte is a literal run
                    goto match_next;       // state 1..3: next byte is a short match
                }
            }
            const size_t high = static_cast<size_t>(t & 8) << 11;
            t &= 7;
            if (t == 0) {
                if (!in_avail(1)) return false;
                while (*ip == 0) { t += 255; ++ip; if (!in_avail(1)) return false; }
                t += 7 + *ip++;
            }
            if (!in_avail(2)) return false;
            size_t d = (static_cast<size_t>(ip[0]) >> 2) + (static_cast<size_t>(ip[1]) << 6);
            ip += 2;
            if (high == 0 && d == 0) {  // end-of-stream marker
                *out_len = static_cast<size_t>(op - out);
                return true;
            }
            if (!copy_match(high + d + 0x4000, t + 2)) return false;
        } else {
            return false;  // unreachable: match entered with t >= 16
        }

    match_done:
        // Trailing literals (0..3) for the next instruction are the low 2 bits of
        // the byte at ip[-2] (the command byte for 1-distance-byte matches, the
        // first distance byte for 2-distance-byte matches).
        t = static_cast<size_t>(ip[-2]) & 3;
        if (t == 0) continue;
    match_next:
        if (!copy_lit(t)) return false;
        if (!in_avail(1)) return false;
        t = *ip++;
        if (t >= 16) goto match;
        {
            if (!in_avail(1)) return false;
            // A short match FOLLOWING a match (length 2) uses a base distance of 1.
            // Only the short match after a *literal run* (after_literal_run, length
            // 3) adds the 0x0800 (M2_MAX_OFFSET) base -- that offset must NOT be
            // applied here, or every match-after-match back-reference is 2048 too
            // far and copy_match fails (aborting the whole block).
            size_t off = 1 + (t >> 2) + (static_cast<size_t>(*ip++) << 2);
            if (!copy_match(off, 2)) return false;
        }
        goto match_done;
    }
}

}  // namespace ft

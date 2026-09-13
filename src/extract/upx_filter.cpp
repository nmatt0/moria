// upx_filter.cpp — UPX un-filters. See upx_filter.hpp for provenance.
#include "extract/upx_filter.hpp"

namespace ft {

namespace {

uint32_t rd_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
uint32_t rd_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
void wr_le32(uint8_t* p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}
uint32_t rd_le24(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16);
}
void wr_le24(uint8_t* p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v >> 16) & 0xff;
}

// x86 cto calltrick family (cto / ctoj / ctok). The unfilter loop is identical
// across the three; only which opcodes are treated as a branch differs:
//   0x24 e8 only, 0x25 e9 only, 0x26/0x36/0x46 e8|e9, 0x49 e8|e9 plus jcc (0f 8x).
// For a branch whose displacement byte-1 equals the cto marker, the big-endian
// operand is converted back to the original little-endian relative displacement.
bool unfilter_cto_family(std::span<uint8_t> buf, uint8_t ftid, uint8_t cto) {
    uint8_t* b = buf.data();
    const size_t n = buf.size();
    if (n < 6) return true;  // nothing to scan (matches UPX's size-5 guard)
    const size_t size5 = n - 5;
    const uint32_t cto_hi = static_cast<uint32_t>(cto) << 24;
    const bool want_e8 = (ftid != 0x25);
    const bool want_e9 = (ftid != 0x24);
    const bool want_jcc = (ftid == 0x49);
    size_t lastcall = 0;
    for (size_t ic = 0; ic < size5; ++ic) {
        const uint8_t op = b[ic];
        bool is_branch = (want_e8 && op == 0xe8) || (want_e9 && op == 0xe9);
        if (!is_branch && want_jcc && ic != 0 && lastcall != ic && b[ic - 1] == 0x0f &&
            op >= 0x80 && op <= 0x8f) {
            is_branch = true;
        }
        if (!is_branch) continue;
        if (b[ic + 1] == cto) {
            uint32_t jc = rd_be32(b + ic + 1);
            wr_le32(b + ic + 1, jc - static_cast<uint32_t>(ic) - 1 - cto_hi);
            ic += 4;
            lastcall = ic + 1;
        }
    }
    return true;
}

// 24-bit ARM calltrick (0x50 little-endian, 0x51 big-endian): every 4-byte word
// whose condition nibble marks a BL has its 24-bit immediate decremented by the
// word index. addvalue is 0 for unpacking.
bool unfilter_ct24arm(std::span<uint8_t> buf, bool big_endian) {
    uint8_t* b = buf.data();
    const size_t n = buf.size();
    if (n < 4) return true;
    const size_t end = n - 4;
    for (size_t i = 0; i < end; i += 4) {
        if (big_endian) {
            if ((b[i] & 0x0f) == 0x0b) {
                uint32_t v = (static_cast<uint32_t>(b[i + 1]) << 16) |
                             (static_cast<uint32_t>(b[i + 2]) << 8) | b[i + 3];
                v = (v - static_cast<uint32_t>(i / 4)) & 0xffffff;
                b[i + 1] = (v >> 16) & 0xff; b[i + 2] = (v >> 8) & 0xff; b[i + 3] = v & 0xff;
            }
        } else {
            if ((b[i + 3] & 0x0f) == 0x0b) {
                uint32_t v = rd_le24(b + i);
                v = (v - static_cast<uint32_t>(i / 4)) & 0xffffff;
                wr_le24(b + i, v);
            }
        }
    }
    return true;
}

// 26-bit ARM64 calltrick (0x52 little-endian): every 4-byte word that is a b/bl
// (top 6 bits 0b000101) has its 26-bit immediate decremented by the word index.
bool unfilter_ct26arm64(std::span<uint8_t> buf) {
    uint8_t* b = buf.data();
    const size_t n = buf.size();
    if (n < 4) return true;
    const size_t end = n - 4;
    for (size_t i = 0; i < end; i += 4) {
        if ((b[i + 3] & 0x7c) == 0x14) {
            uint32_t full = rd_le32(b + i);
            uint32_t v = (full & 0x03ffffff);
            v = (v - static_cast<uint32_t>(i / 4)) & 0x03ffffff;
            full = (full & ~0x03ffffffu) | v;
            wr_le32(b + i, full);
        }
    }
    return true;
}

}  // namespace

bool upx_filter_supported(uint8_t ftid) {
    switch (ftid) {
        case 0x00:  // no filter
        case 0x24: case 0x25: case 0x26: case 0x36: case 0x46: case 0x49:  // x86
        case 0x50: case 0x51:  // ARM
        case 0x52:             // ARM64
            return true;
        default:
            return false;
    }
}

bool upx_unfilter(std::span<uint8_t> buf, uint8_t ftid, uint8_t cto) {
    switch (ftid) {
        case 0x00:
            return true;
        case 0x24: case 0x25: case 0x26: case 0x36: case 0x46: case 0x49:
            return unfilter_cto_family(buf, ftid, cto);
        case 0x50:
            return unfilter_ct24arm(buf, /*big_endian=*/false);
        case 0x51:
            return unfilter_ct24arm(buf, /*big_endian=*/true);
        case 0x52:
            return unfilter_ct26arm64(buf);
        default:
            return false;
    }
}

}  // namespace ft

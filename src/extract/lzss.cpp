// lzss.cpp — VBF (qvbf) LZSS decoder. See lzss.hpp.
//
// Bit stream is MSB-first within each byte. Token loop:
//   bit 1  -> literal: next 8 bits are the byte.
//   bit 0  -> reference: EI(10) index bits + EJ(4) length bits.
//             index 0 == end-of-stream. Otherwise copy (length + 2) bytes from
//             the 1024-entry ring starting at (index - 1).
// The ring mirrors the decoder in the ford-pscm-re toolchain (init 0x20), which
// round-trips every observed Ford PSCM block.
#include "extract/lzss.hpp"

namespace ft {

namespace {

constexpr int kEI = 10;              // index bits
constexpr int kEJ = 4;               // length bits
constexpr size_t kN = size_t(1) << kEI;  // ring size (1024)
constexpr uint8_t kRingInit = 0x20;      // space

// MSB-first bit reader over a byte span. Returns -1 once the span is exhausted.
class BitReader {
public:
    explicit BitReader(std::span<const uint8_t> data) : data_(data) {}

    int get(int n) {
        int x = 0;
        for (int i = 0; i < n; ++i) {
            if (mask_ == 0) {
                if (pos_ >= data_.size()) return -1;
                buf_ = data_[pos_++];
                mask_ = 0x80;
            }
            x = (x << 1) | ((buf_ & mask_) ? 1 : 0);
            mask_ >>= 1;
        }
        return x;
    }

private:
    std::span<const uint8_t> data_;
    size_t pos_ = 0;
    unsigned buf_ = 0;
    unsigned mask_ = 0;
};

}  // namespace

std::optional<std::vector<uint8_t>> lzss_vbf_decompress(std::span<const uint8_t> src,
                                                        size_t max_out) {
    std::vector<uint8_t> ring(kN, kRingInit);
    std::vector<uint8_t> out;
    BitReader br(src);
    size_t r = 0;

    for (;;) {
        int c = br.get(1);
        if (c < 0) break;  // stream exhausted with no end marker: return what we have
        if (c) {
            int ch = br.get(8);
            if (ch < 0) break;
            if (out.size() >= max_out) break;
            out.push_back(static_cast<uint8_t>(ch));
            ring[r] = static_cast<uint8_t>(ch);
            r = (r + 1) & (kN - 1);
        } else {
            int i = br.get(kEI);
            if (i < 0) break;
            if (i == 0) break;  // end-of-stream marker
            int j = br.get(kEJ);
            if (j < 0) break;
            size_t pos = static_cast<size_t>(i - 1);
            int len = j + 2;
            for (int k = 0; k < len; ++k) {
                uint8_t ch = ring[(pos + static_cast<size_t>(k)) & (kN - 1)];
                if (out.size() >= max_out) return out;
                out.push_back(ch);
                ring[r] = ch;
                r = (r + 1) & (kN - 1);
            }
        }
    }
    return out;
}

}  // namespace ft

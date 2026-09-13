// ucl.cpp — NRV2B / NRV2D / NRV2E decompressors. See ucl.hpp for the method-byte
// map and provenance.
//
// The three algorithms share the same token loop:
//   * a run of literal bytes (one "1" bit each, then the raw byte),
//   * a match: a coded offset, then a coded length, then a back-copy.
// They differ only in the offset code (NRV2B single gamma vs NRV2D/2E double
// gamma) and the length code. The bit reader differs only by word width. So the
// reader is one class parameterized by width, and each algorithm is one function
// that drives it. Every input read is bounds-checked; the output stops at the
// caller's out_len (UPX always supplies the exact decompressed size per block).
#include "extract/ucl.hpp"

#include <cstddef>
#include <cstdint>
#include <utility>

namespace ft {

namespace {

enum class Width { W8, W16, W32 };

// Cap on the coded match offset before the escape byte, matching UCL's
// LOOKBEHIND_OVERRUN guard. Bounds the gamma loop so a malformed / truncated
// stream (whose bit refills 0-fill past end-of-input) cannot spin unbounded.
constexpr size_t kMaxOff = 0xffffffu + 3;

// MSB-first bit reader matching UCL's getbit_8 / _le16 / _le32. Bits and raw
// bytes share ONE input cursor, exactly as UCL's `ilen` does: a bit-word refill
// reads `width` bytes little-endian and advances the cursor by that many; a
// literal/escape byte read advances it by one. The current word keeps its
// remaining bits across intervening byte reads (the word was already pulled from
// the stream), so literals are drawn from bytes past the current word. Missing
// input bytes at end-of-stream read as 0 for bit refills — harmless because
// decode stops at out_len before those bits are consumed on a well-formed
// stream; getbyte() instead reports exhaustion so a malformed stream fails on a
// bounds-checked literal/escape rather than reading out of bounds.
class BitReader {
public:
    BitReader(std::span<const uint8_t> data, Width w) : data_(data), width_(w) {}

    int getbit() {
        if (bits_left_ == 0) {
            const int nbytes = (width_ == Width::W8) ? 1 : (width_ == Width::W16) ? 2 : 4;
            uint32_t v = 0;
            for (int i = 0; i < nbytes; ++i) {
                uint8_t b = (pos_ < data_.size()) ? data_[pos_] : 0;
                ++pos_;
                v |= static_cast<uint32_t>(b) << (8 * i);  // little-endian word
            }
            word_ = v;
            bits_left_ = nbytes * 8;
        }
        --bits_left_;
        return static_cast<int>((word_ >> bits_left_) & 1);
    }

    // Next raw byte from the input (used for literals and the offset escape),
    // from the same cursor the bit refills advance. Returns -1 at exhaustion.
    int getbyte() {
        if (pos_ >= data_.size()) return -1;
        return data_[pos_++];
    }

private:
    std::span<const uint8_t> data_;
    Width width_;
    size_t pos_ = 0;        // shared bit-word + raw-byte cursor (UCL's ilen)
    uint32_t word_ = 0;
    int bits_left_ = 0;
};

// Copy a match: `count` bytes from `out[out.size()-off]` forward, byte by byte so
// overlapping copies (off < count) replicate correctly. Fails if off reaches
// before the start of output or the copy would exceed out_len.
bool emit_match(std::vector<uint8_t>& out, size_t off, size_t count, size_t out_len) {
    if (off == 0 || off > out.size()) return false;
    if (count > out_len - out.size()) return false;
    size_t src = out.size() - off;
    for (size_t i = 0; i < count; ++i) out.push_back(out[src + i]);
    return true;
}

// One literal byte. Fails on input exhaustion or output overflow.
bool emit_literal(BitReader& br, std::vector<uint8_t>& out, size_t out_len) {
    if (out.size() >= out_len) return false;
    int c = br.getbyte();
    if (c < 0) return false;
    out.push_back(static_cast<uint8_t>(c));
    return true;
}

// Decode the little-endian length gamma tail shared by NRV2B/2D: starting from a
// primed value, read (bit) pairs until a stop bit. Returns the assembled length.
// Caller adds the algorithm's constant. `ok` is cleared on malformed input.
size_t gamma_tail(BitReader& br, size_t start, bool& ok) {
    size_t m_len = start;
    do {
        m_len = m_len * 2 + static_cast<size_t>(br.getbit());
        if (m_len > (1u << 30)) { ok = false; return 0; }  // runaway guard
    } while (!br.getbit());
    return m_len;
}

// NRV2B: single-gamma offset, 2-bit-then-gamma length.
std::optional<std::vector<uint8_t>> nrv2b(BitReader& br, size_t out_len) {
    std::vector<uint8_t> out;
    out.reserve(out_len);
    size_t last_off = 1;
    for (;;) {
        while (br.getbit()) {
            if (!emit_literal(br, out, out_len)) return std::nullopt;
            if (out.size() == out_len) return out;
        }
        size_t m_off = 1;
        for (;;) {  // NRV2B: single interleaved gamma
            m_off = m_off * 2 + static_cast<size_t>(br.getbit());
            if (m_off > kMaxOff) return std::nullopt;  // runaway (0-fill past EOF)
            if (br.getbit()) break;
        }
        if (m_off == 2) {
            m_off = last_off;
        } else {
            int b = br.getbyte();
            if (b < 0) return std::nullopt;
            m_off = (m_off - 3) * 256 + static_cast<size_t>(b);
            if (m_off == 0xffffffffu) break;  // end-of-stream
            last_off = ++m_off;
        }
        size_t m_len = static_cast<size_t>(br.getbit());
        m_len = m_len * 2 + static_cast<size_t>(br.getbit());
        if (m_len == 0) {
            bool ok = true;
            m_len = gamma_tail(br, 1, ok) + 2;
            if (!ok) return std::nullopt;
        }
        m_len += (m_off > 0xd00) ? 1 : 0;
        if (!emit_match(out, m_off, m_len + 1, out_len)) return std::nullopt;
        if (out.size() == out_len) return out;
    }
    return (out.size() == out_len) ? std::optional(std::move(out)) : std::nullopt;
}

// NRV2D: double-gamma offset (low bit of the escape becomes a length bit),
// 2-bit-then-gamma length.
std::optional<std::vector<uint8_t>> nrv2d(BitReader& br, size_t out_len) {
    std::vector<uint8_t> out;
    out.reserve(out_len);
    size_t last_off = 1;
    for (;;) {
        while (br.getbit()) {
            if (!emit_literal(br, out, out_len)) return std::nullopt;
            if (out.size() == out_len) return out;
        }
        size_t m_off = 1;
        for (;;) {  // NRV2D/2E: double interleaved gamma
            m_off = m_off * 2 + static_cast<size_t>(br.getbit());
            if (br.getbit()) break;
            m_off = (m_off - 1) * 2 + static_cast<size_t>(br.getbit());
            if (m_off > kMaxOff) return std::nullopt;  // runaway (0-fill past EOF)
        }
        size_t m_len;
        if (m_off == 2) {
            m_off = last_off;
            m_len = static_cast<size_t>(br.getbit());
        } else {
            int b = br.getbyte();
            if (b < 0) return std::nullopt;
            m_off = (m_off - 3) * 256 + static_cast<size_t>(b);
            if (m_off == 0xffffffffu) break;  // end-of-stream
            m_len = (~m_off) & 1;  // low bit of the escape is a length bit
            m_off >>= 1;
            last_off = ++m_off;
        }
        m_len = m_len * 2 + static_cast<size_t>(br.getbit());
        if (m_len == 0) {
            bool ok = true;
            m_len = gamma_tail(br, 1, ok) + 2;
            if (!ok) return std::nullopt;
        }
        m_len += (m_off > 0x500) ? 1 : 0;
        if (!emit_match(out, m_off, m_len + 1, out_len)) return std::nullopt;
        if (out.size() == out_len) return out;
    }
    return (out.size() == out_len) ? std::optional(std::move(out)) : std::nullopt;
}

// NRV2E: double-gamma offset (as NRV2D), distinct length code.
std::optional<std::vector<uint8_t>> nrv2e(BitReader& br, size_t out_len) {
    std::vector<uint8_t> out;
    out.reserve(out_len);
    size_t last_off = 1;
    for (;;) {
        while (br.getbit()) {
            if (!emit_literal(br, out, out_len)) return std::nullopt;
            if (out.size() == out_len) return out;
        }
        size_t m_off = 1;
        for (;;) {  // NRV2D/2E: double interleaved gamma
            m_off = m_off * 2 + static_cast<size_t>(br.getbit());
            if (br.getbit()) break;
            m_off = (m_off - 1) * 2 + static_cast<size_t>(br.getbit());
            if (m_off > kMaxOff) return std::nullopt;  // runaway (0-fill past EOF)
        }
        size_t m_len;
        if (m_off == 2) {
            m_off = last_off;
            m_len = static_cast<size_t>(br.getbit());
        } else {
            int b = br.getbyte();
            if (b < 0) return std::nullopt;
            m_off = (m_off - 3) * 256 + static_cast<size_t>(b);
            if (m_off == 0xffffffffu) break;  // end-of-stream
            m_len = (~m_off) & 1;
            m_off >>= 1;
            last_off = ++m_off;
        }
        if (m_len) {
            m_len = 1 + static_cast<size_t>(br.getbit());
        } else if (br.getbit()) {
            m_len = 3 + static_cast<size_t>(br.getbit());
        } else {
            bool ok = true;
            m_len = gamma_tail(br, 1, ok) + 3;
            if (!ok) return std::nullopt;
        }
        m_len += (m_off > 0x500) ? 1 : 0;
        if (!emit_match(out, m_off, m_len + 1, out_len)) return std::nullopt;
        if (out.size() == out_len) return out;
    }
    return (out.size() == out_len) ? std::optional(std::move(out)) : std::nullopt;
}

Width width_of(uint8_t method) {
    // 2/5/8 -> LE32, 3/6/9 -> _8, 4/7/10 -> LE16
    switch (method) {
        case 3: case 6: case 9: return Width::W8;
        case 4: case 7: case 10: return Width::W16;
        default: return Width::W32;  // 2/5/8
    }
}

}  // namespace

bool ucl_method_supported(uint8_t method) { return method >= 2 && method <= 10; }

std::optional<std::vector<uint8_t>> ucl_nrv_decompress(uint8_t method,
                                                       std::span<const uint8_t> src,
                                                       size_t out_len) {
    if (!ucl_method_supported(method)) return std::nullopt;
    if (out_len == 0) return std::vector<uint8_t>{};
    BitReader br(src, width_of(method));
    switch (method) {
        case 2: case 3: case 4: return nrv2b(br, out_len);
        case 5: case 6: case 7: return nrv2d(br, out_len);
        case 8: case 9: case 10: return nrv2e(br, out_len);
        default: return std::nullopt;
    }
}

}  // namespace ft

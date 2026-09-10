// lzari.cpp — LZARI decompressor. See lzari.hpp for source details.
//
// A faithful port of the recovered decode path (StartDecode, DecodeChar,
// DecodePosition, StartModel, UpdateModel, the two binary searches, GetBit).
// The adaptive char model reorders symbols by frequency (order/revorder inverse
// permutation), rebuilding when the total exceeds 0x7ffe; the position model is
// built once and never updated. All coder products are done in 64-bit because
// total*(value-low+1) overflows 32 bits near the top of the range.
#include "extract/lzari.hpp"

#include <array>
#include <cstring>

namespace ft {

namespace {

constexpr int kN = 4096;         // ring buffer size
constexpr int kF = 60;           // max match length
constexpr int kThreshold = 2;    // shorter matches are stored literally
constexpr int kNChar = 256 - kThreshold + kF;  // 314: literal/length alphabet

class Decoder {
public:
    Decoder(std::span<const uint8_t> data, uint32_t expected)
        : data_(data), expected_(expected) {
        for (int s = 0; s < kNChar; ++s) order_[s] = s + 1;
        for (int j = 0; j < kNChar; ++j) revorder_[j] = j;
        for (int j = 0; j < kNChar; ++j) freq_[j] = 1;
        for (int j = 0; j <= kNChar; ++j) cumfreq_[j] = kNChar - j;  // cumfreq_[kNChar] = 0

        // Position model: fixed suffix-cumulative table, built once.
        cumfreq_pos_[kN] = 0;
        int denom = 4296;
        for (int n = 0; n < kN; ++n) {
            int idx = kN - 1 - n;
            cumfreq_pos_[idx] = 10000 / denom + cumfreq_pos_[idx + 1];
            --denom;
        }

        low_ = 0;
        high_ = 0x20000;
        value_ = 0;
        for (int i = 0; i < 17; ++i) value_ = (value_ << 1) | get_bit();
    }

    uint32_t expected() const { return expected_; }

    // Decode one code: < 256 literal byte, >= 256 a match (length = code - 253).
    int decode_char() {
        int64_t total = cumfreq_[0];
        int64_t rng = high_ - low_;
        int64_t target = (total * (value_ - low_ + 1) - 1) / rng;
        int rank = search_sym(target);
        high_ = static_cast<int64_t>(cumfreq_[rank - 1]) * rng / total + low_;
        low_ = rng * static_cast<int64_t>(cumfreq_[rank]) / total + low_;
        renorm();
        int symbol = revorder_[rank - 1];
        update_model(rank);
        return symbol;
    }

    int decode_position() {
        int64_t total = cumfreq_pos_[0];
        int64_t rng = high_ - low_;
        int64_t target = (total * (value_ - low_ + 1) - 1) / rng;
        int pos = search_pos(target);
        high_ = static_cast<int64_t>(cumfreq_pos_[pos]) * rng / total + low_;
        low_ = rng * static_cast<int64_t>(cumfreq_pos_[pos + 1]) / total + low_;
        renorm();
        return pos;
    }

private:
    int get_bit() {
        bitmask_ >>= 1;
        if (bitmask_ == 0) {
            uint8_t b = (cursor_ < data_.size()) ? data_[cursor_] : 0;
            ++cursor_;
            bitbuf_ = b;
            bitmask_ = 0x80;
        }
        return (bitbuf_ & bitmask_) ? 1 : 0;
    }

    // Renormalize until the encoder's STOP condition; leaves low/high/value at
    // that point for the next decode (no final shift is taken).
    void renorm() {
        while (true) {
            if (low_ < 0x10000) {
                if (low_ < 0x8000 || high_ > 0x18000) {
                    if (high_ > 0x10000) return;  // STOP
                    // E1: no-op
                } else {
                    value_ -= 0x8000; high_ -= 0x8000; low_ -= 0x8000;  // E3
                }
            } else {
                value_ -= 0x10000; low_ -= 0x10000; high_ -= 0x10000;  // E2
            }
            low_ <<= 1;
            high_ <<= 1;
            value_ = (value_ << 1) | get_bit();
        }
    }

    int search_sym(int64_t target) const {
        int lo = 1, hi = kNChar;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            if (target < cumfreq_[mid]) lo = mid + 1; else hi = mid;
        }
        return hi;
    }

    int search_pos(int64_t target) const {
        int lo = 1, hi = kN;
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            if (target < cumfreq_pos_[mid]) lo = mid + 1; else hi = mid;
        }
        return lo - 1;
    }

    void rebuild() {
        int running = 0;
        for (int k = kNChar - 1; k >= 0; --k) {
            cumfreq_[k + 1] = running;
            freq_[k] = (freq_[k] + 1) >> 1;
            running += freq_[k];
        }
        cumfreq_[0] = running;
    }

    void update_model(int rank) {
        if (cumfreq_[0] > 0x7ffe) rebuild();

        int my_freq = freq_[rank - 1];
        // Walk up past the run of symbols tied at my_freq; land at the top.
        int prev_idx = rank;
        int cur_idx = rank;
        while (true) {
            prev_idx = cur_idx;
            cur_idx -= 1;
            int neighbor = (prev_idx - 2 >= 0) ? freq_[prev_idx - 2] : freq_sentinel_;
            if (neighbor != my_freq) break;
        }
        int final_idx = prev_idx;

        if (final_idx < rank) {  // swap the updated symbol to the top of its group
            int old_symbol = revorder_[final_idx - 1];
            int moved_symbol = revorder_[rank - 1];
            revorder_[final_idx - 1] = moved_symbol;
            revorder_[rank - 1] = old_symbol;
            order_[old_symbol] = rank;
            order_[moved_symbol] = final_idx;
        }

        freq_[final_idx - 1] += 1;
        for (int k = final_idx - 1; k >= 0; --k) cumfreq_[k] += 1;
    }

    std::span<const uint8_t> data_;
    uint32_t expected_;
    size_t cursor_ = 4;   // bytes 0..3 are the size prefix
    int bitbuf_ = 0;
    int bitmask_ = 0;

    int64_t low_ = 0, high_ = 0, value_ = 0;

    std::array<int, kNChar> order_{};
    std::array<int, kNChar> revorder_{};
    std::array<int, kNChar> freq_{};
    std::array<int, kNChar + 1> cumfreq_{};
    int freq_sentinel_ = 0;  // FREQ[-1]: set once, never changes
    std::array<int, kN + 1> cumfreq_pos_{};
};

}  // namespace

std::optional<std::vector<uint8_t>> lzari_decompress(std::span<const uint8_t> in, size_t max_out) {
    if (in.size() < 4) return std::nullopt;
    uint32_t expected;
    std::memcpy(&expected, in.data(), 4);  // little-endian on all supported hosts
    if (expected > max_out) return std::nullopt;
    if (expected == 0) return std::vector<uint8_t>{};

    Decoder dec(in, expected);
    std::vector<uint8_t> out;
    out.reserve(expected);

    std::array<uint8_t, kN> text{};
    for (int i = 0; i < kN - kF; ++i) text[i] = 0x20;  // pre-fill with spaces
    int r = kN - kF;

    while (out.size() < expected) {
        int c = dec.decode_char();
        if (c < 256) {
            out.push_back(static_cast<uint8_t>(c));
            text[r] = static_cast<uint8_t>(c);
            r = (r + 1) & (kN - 1);
        } else {
            int pos = dec.decode_position();
            int i2 = (r - pos - 1) & (kN - 1);
            int length = c - 253;
            for (int k = 0; k < length && out.size() < expected; ++k) {
                uint8_t b = text[i2 & (kN - 1)];
                out.push_back(b);
                text[r] = b;
                r = (r + 1) & (kN - 1);
                ++i2;
            }
        }
    }

    return out;
}

}  // namespace ft

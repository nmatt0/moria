// jzlzma.cpp — Ingenic jzlzma decoder. See jzlzma.hpp for the format.
//
// A faithful port of the recovered decode path: an LSB-first bit reader (bits
// are consumed from bit 0 of each byte, values accumulate MSB-first), LZMA's
// length bands and position-slot distance table with the hardware's
// bit-reversal quirk, and the four-slot rep cache with its rotation rules.
#include "extract/jzlzma.hpp"

#include <algorithm>

namespace ft {

namespace {

// Position-slot thresholds, as in LZMA (kStartPosModelIndex/kEndPosModelIndex).
constexpr uint32_t kStartPosSlot = 4;
constexpr uint32_t kEndPosSlot = 14;
constexpr uint32_t kAlignBits = 4;

class BitReader {
public:
    explicit BitReader(std::span<const uint8_t> d) : d_(d) {}

    // Next raw bit, or -1 once the input is exhausted.
    int next() {
        if (cur_ >= d_.size()) return -1;
        int b = (d_[cur_] >> bit_) & 1;
        if (++bit_ == 8) {
            bit_ = 0;
            ++cur_;
        }
        return b;
    }

    // Read `n` bits, MSB-first, into `out`. False if the input ends first.
    bool read(uint32_t n, uint32_t& out) {
        out = 0;
        for (uint32_t i = 0; i < n; ++i) {
            int b = next();
            if (b < 0) return false;
            out = (out << 1) | static_cast<uint32_t>(b);
        }
        return true;
    }

    // Whole input bytes touched so far (the final opcode's tail bits count as
    // a consumed byte).
    size_t consumed() const { return cur_ + (bit_ != 0 ? 1 : 0); }

private:
    std::span<const uint8_t> d_;
    size_t cur_ = 0;
    uint32_t bit_ = 0;
};

uint32_t reverse_bits(uint32_t v, uint32_t bits) {
    uint32_t r = 0;
    for (uint32_t i = 0; i < bits; ++i) r = (r << 1) | ((v >> i) & 1);
    return r;
}

// Match length, LZMA's three bands: 2..9, 10..17, 18..273.
std::optional<size_t> decode_length(BitReader& br) {
    int b = br.next();
    if (b < 0) return std::nullopt;
    uint32_t v = 0;
    if (b == 0) {
        if (!br.read(3, v)) return std::nullopt;
        return static_cast<size_t>(v) + 2;
    }
    b = br.next();
    if (b < 0) return std::nullopt;
    if (b == 0) {
        if (!br.read(3, v)) return std::nullopt;
        return static_cast<size_t>(v) + 10;
    }
    if (!br.read(8, v)) return std::nullopt;
    return static_cast<size_t>(v) + 18;
}

// Match distance minus one ("pos"), LZMA's position-slot table: a 6-bit slot,
// then `n` extra bits — stored bit-reversed for slots 4..13, and split into a
// natural-order high part plus a reversed 4-bit align part for slots >= 14.
std::optional<uint32_t> decode_dist(BitReader& br) {
    uint32_t slot = 0;
    if (!br.read(6, slot)) return std::nullopt;
    if (slot < kStartPosSlot) return slot;
    const uint32_t n = (slot >> 1) - 1;  // 1..30 direct bits
    const uint32_t base = (2 | (slot & 1)) << n;
    uint32_t v = 0;
    if (slot < kEndPosSlot) {
        if (!br.read(n, v)) return std::nullopt;
        return base + reverse_bits(v, n);
    }
    if (!br.read(n - kAlignBits, v)) return std::nullopt;
    uint32_t align = 0;
    if (!br.read(kAlignBits, align)) return std::nullopt;
    return base + (v << kAlignBits) + reverse_bits(align, kAlignBits);
}

}  // namespace

std::optional<std::vector<uint8_t>> jzlzma_decode(std::span<const uint8_t> stream,
                                                  size_t out_size, size_t* consumed,
                                                  bool allow_short) {
    if (out_size > kJzlzmaMaxOut) return std::nullopt;
    std::vector<uint8_t> out;
    if (out_size == 0) return out;
    out.reserve(out_size);

    BitReader br(stream);
    uint32_t reps[4] = {0, 0, 0, 0};

    // In allow_short mode any failure after real output is a stop, not an
    // error: return the produced prefix (the caller checks the shortfall).
    auto stop = [&](bool failed) -> std::optional<std::vector<uint8_t>> {
        if (!failed) return std::nullopt;  // unused for success paths
        if (allow_short && !out.empty()) {
            if (consumed) *consumed = br.consumed();
            return std::move(out);
        }
        return std::nullopt;
    };

    while (out.size() < out_size) {
        int b = br.next();
        if (b < 0) return stop(true);  // input ended before the declared size
        if (b == 0) {                    // literal
            uint32_t v = 0;
            if (!br.read(8, v)) return stop(true);
            out.push_back(static_cast<uint8_t>(v));
            continue;
        }

        // Match opcode tree. The new-distance form reads length first, then the
        // distance; the rep forms rotate an existing slot to the front and take
        // their length after the opcode bits.
        size_t size = 0;
        b = br.next();
        if (b < 0) return stop(true);
        if (b == 0) {  // new distance
            auto len = decode_length(br);
            if (!len) return stop(true);
            auto dist = decode_dist(br);
            if (!dist) return stop(true);
            reps[3] = reps[2];
            reps[2] = reps[1];
            reps[1] = reps[0];
            reps[0] = *dist;
            size = *len;
        } else {
            b = br.next();
            if (b < 0) return stop(true);
            if (b == 0) {  // rep0
                b = br.next();
                if (b < 0) return stop(true);
                if (b == 0) size = 1;  // one-byte rep0 shortcut; else explicit length
            } else {         // rep1/rep2/rep3
                b = br.next();
                if (b < 0) return stop(true);
                uint32_t idx = 1;
                if (b != 0) {
                    b = br.next();
                    if (b < 0) return stop(true);
                    idx = (b == 0) ? 2 : 3;
                }
                uint32_t v = reps[idx];
                for (uint32_t i = idx; i > 0; --i) reps[i] = reps[i - 1];
                reps[0] = v;
            }
        }
        if (size == 0) {
            auto len = decode_length(br);
            if (!len) return stop(true);
            size = *len;
        }

        const size_t dist = static_cast<size_t>(reps[0]) + 1;
        if (dist > out.size()) return stop(true);  // reaches before the output start
        const size_t start = out.size() - dist;
        // Byte-by-byte so an overlapping match (distance < length) replicates,
        // as in LZMA. A final match claiming past out_size is corruption, but
        // harmless to satisfy: cap it and the stream is done either way.
        const size_t take = std::min(size, out_size - out.size());
        for (size_t k = 0; k < take; ++k) out.push_back(out[start + k]);
    }
    if (consumed) *consumed = br.consumed();
    return out;
}

}  // namespace ft

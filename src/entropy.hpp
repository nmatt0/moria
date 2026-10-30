// entropy.hpp — Shannon entropy over a byte span, normalized to bits/byte (0-8).
// Used to flag encrypted/compressed unidentified regions (the -E pass). Cheap:
// one pass, 256-bucket histogram.
#pragma once

#include <array>
#include <cmath>
#include <cstdint>
#include <span>

namespace ft {

inline double shannon_entropy(std::span<const uint8_t> data) {
    if (data.empty()) return 0.0;
    std::array<uint64_t, 256> counts{};
    for (uint8_t b : data) counts[b]++;
    const double inv = 1.0 / static_cast<double>(data.size());
    double e = 0.0;
    for (uint64_t c : counts) {
        if (c == 0) continue;
        double p = static_cast<double>(c) * inv;
        e -= p * std::log2(p);
    }
    return e;  // 0 (uniform byte) .. 8 (max, e.g. random/encrypted)
}

// Fraction of `data` made up of its single most common byte value (0..1).
// Length-independent, unlike Shannon entropy, which is capped at log2(len) on a
// short span: a 52-byte span cannot exceed ~5.7 bits/byte however random it is.
// So this is the reliable "is this really compressed/high-entropy data" test for
// short spans. Compressed/encrypted output is near-uniform (no value dominates);
// zero padding or an erase pattern is dominated by one value (approaches 1.0).
inline double max_byte_fraction(std::span<const uint8_t> data) {
    if (data.empty()) return 1.0;
    std::array<uint64_t, 256> counts{};
    for (uint8_t b : data) counts[b]++;
    uint64_t mx = 0;
    for (uint64_t c : counts)
        if (c > mx) mx = c;
    return static_cast<double>(mx) / static_cast<double>(data.size());
}

}  // namespace ft

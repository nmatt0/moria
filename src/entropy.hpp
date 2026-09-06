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

}  // namespace ft

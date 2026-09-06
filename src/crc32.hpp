// crc32.hpp — IEEE/zlib CRC-32 (poly 0xEDB88320), used by the uImage validator
// to verify the header CRC. Header-only, table built once.
#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace ft {

inline const std::array<uint32_t, 256>& crc32_table() {
    static const auto table = [] {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();
    return table;
}

// Standard IEEE/zlib CRC-32 (init ~0, final XOR). Used by uImage.
inline uint32_t crc32_ieee(std::span<const uint8_t> data) {
    const auto& table = crc32_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : data) crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

// Table CRC with a caller-chosen init and NO final inversion.
inline uint32_t crc32_raw(uint32_t init, std::span<const uint8_t> data) {
    const auto& table = crc32_table();
    uint32_t crc = init;
    for (uint8_t b : data) crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8);
    return crc;
}

// JFFS2: init 0, no inversion.
inline uint32_t crc32_jffs2(std::span<const uint8_t> data) { return crc32_raw(0, data); }

// UBI/UBIFS: init 0xFFFFFFFF, no final inversion.
inline uint32_t crc32_ubi(std::span<const uint8_t> data) { return crc32_raw(0xFFFFFFFFu, data); }

}  // namespace ft

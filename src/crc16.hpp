// crc16.hpp — CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection, no
// final XOR), used by the VBF validator/extractor to verify each block's stored
// CRC16 over its (decompressed) payload. Header-only.
#pragma once

#include <cstdint>
#include <span>

namespace ft {

inline uint16_t crc16_ccitt(std::span<const uint8_t> data) {
    uint16_t crc = 0xFFFF;
    for (uint8_t b : data) {
        crc ^= static_cast<uint16_t>(b) << 8;
        for (int k = 0; k < 8; ++k)
            crc = (crc & 0x8000) ? static_cast<uint16_t>((crc << 1) ^ 0x1021)
                                 : static_cast<uint16_t>(crc << 1);
    }
    return crc;
}

}  // namespace ft

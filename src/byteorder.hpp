// byteorder.hpp — endian loads from an already-in-memory buffer.
//
// For bytes read straight from the source image, use Reader (bounds-checked).
// These are for buffers a parser already holds and has range-checked — a
// decompressed metadata block, a b-tree leaf, a catalog record — where indexing
// is hot and the extent is known. The caller guarantees `off + N <= size`; these
// index directly (no bounds check) and never allocate or throw.
#pragma once

#include <cstdint>
#include <span>

#include "reader.hpp"  // Endian

namespace ft {

inline uint16_t load_le16(const uint8_t* p) { return uint16_t(uint16_t(p[0]) | (uint16_t(p[1]) << 8)); }
inline uint32_t load_le32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline uint64_t load_le64(const uint8_t* p) {
    return uint64_t(load_le32(p)) | (uint64_t(load_le32(p + 4)) << 32);
}
inline uint16_t load_be16(const uint8_t* p) { return uint16_t(uint16_t(p[1]) | (uint16_t(p[0]) << 8)); }
inline uint32_t load_be32(const uint8_t* p) {
    return uint32_t(p[3]) | (uint32_t(p[2]) << 8) | (uint32_t(p[1]) << 16) | (uint32_t(p[0]) << 24);
}
inline uint64_t load_be64(const uint8_t* p) {
    return (uint64_t(load_be32(p)) << 32) | uint64_t(load_be32(p + 4));
}

inline uint16_t load_u16(const uint8_t* p, Endian e) {
    return e == Endian::Little ? load_le16(p) : load_be16(p);
}
inline uint32_t load_u32(const uint8_t* p, Endian e) {
    return e == Endian::Little ? load_le32(p) : load_be32(p);
}
inline uint64_t load_u64(const uint8_t* p, Endian e) {
    return e == Endian::Little ? load_le64(p) : load_be64(p);
}

// span + offset conveniences (caller ensures off + N <= b.size()).
inline uint16_t load_le16(std::span<const uint8_t> b, size_t o) { return load_le16(b.data() + o); }
inline uint32_t load_le32(std::span<const uint8_t> b, size_t o) { return load_le32(b.data() + o); }
inline uint64_t load_le64(std::span<const uint8_t> b, size_t o) { return load_le64(b.data() + o); }
inline uint16_t load_be16(std::span<const uint8_t> b, size_t o) { return load_be16(b.data() + o); }
inline uint32_t load_be32(std::span<const uint8_t> b, size_t o) { return load_be32(b.data() + o); }
inline uint64_t load_be64(std::span<const uint8_t> b, size_t o) { return load_be64(b.data() + o); }
inline uint16_t load_u16(std::span<const uint8_t> b, size_t o, Endian e) { return load_u16(b.data() + o, e); }
inline uint32_t load_u32(std::span<const uint8_t> b, size_t o, Endian e) { return load_u32(b.data() + o, e); }
inline uint64_t load_u64(std::span<const uint8_t> b, size_t o, Endian e) { return load_u64(b.data() + o, e); }

}  // namespace ft

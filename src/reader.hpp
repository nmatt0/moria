// reader.hpp — the one bounds-checked buffer reader.
//
// Design guardrail:
// ALL access to file bytes goes through Reader. No code outside this file does
// raw pointer + length arithmetic. Every read returns std::optional and is
// range-checked, so an attacker-controlled offset/size in a header can never
// cause an out-of-bounds read — it just yields std::nullopt the caller handles.
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <type_traits>

namespace ft {

enum class Endian { Little, Big };

inline const char* endian_name(Endian e) {
    return e == Endian::Little ? "little" : "big";
}

// Endian-swap any trivially-copyable integer (no-op for 1-byte).
template <class T>
inline T byteswap_generic(T v) {
    if constexpr (sizeof(T) == 1) {
        return v;
    } else {
        std::array<uint8_t, sizeof(T)> b{};
        std::memcpy(b.data(), &v, sizeof(T));
        std::reverse(b.begin(), b.end());
        std::memcpy(&v, b.data(), sizeof(T));
        return v;
    }
}

class Reader {
public:
    explicit Reader(std::span<const uint8_t> data) : data_(data) {}

    std::span<const uint8_t> data() const { return data_; }
    size_t size() const { return data_.size(); }

    // Read an integer at `off` in the given byte order. nullopt on overrun.
    template <class T>
    std::optional<T> at(size_t off, Endian e) const {
        static_assert(std::is_integral_v<T>, "at<T> requires an integer type");
        if (off > data_.size() || sizeof(T) > data_.size() - off) return std::nullopt;
        T v{};
        std::memcpy(&v, data_.data() + off, sizeof(T));
        const bool swap = (e == Endian::Big) ? (std::endian::native == std::endian::little)
                                             : (std::endian::native == std::endian::big);
        if (swap) v = byteswap_generic(v);
        return v;
    }

    // Borrow n raw bytes at `off`. nullopt on overrun.
    std::optional<std::span<const uint8_t>> bytes(size_t off, size_t n) const {
        if (off > data_.size() || n > data_.size() - off) return std::nullopt;
        return data_.subspan(off, n);
    }

    // True if the literal pattern occurs at exactly `off`.
    bool matches_at(size_t off, std::span<const uint8_t> pattern) const {
        auto b = bytes(off, pattern.size());
        if (!b) return false;
        return std::equal(pattern.begin(), pattern.end(), b->begin());
    }

private:
    std::span<const uint8_t> data_;
};

}  // namespace ft

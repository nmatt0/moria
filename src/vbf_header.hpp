// vbf_header.hpp — shared parsing of a VBF ASCII header.
//
// A VBF file begins with `vbf_version = X.Y;` then a `header { ... }` block; the
// binary block chain starts immediately after the header's closing brace. These
// helpers locate that closing brace (quote-aware, so a `}` inside a quoted
// string does not close the block) and pull a few text fields for metadata.
#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>

#include "reader.hpp"

namespace ft {

namespace vbf {

constexpr size_t kMaxHeader = 1u << 20;  // 1 MiB cap on the ASCII header scan

// Offset (relative to the file) one past the header block's closing brace, i.e.
// where the binary block chain begins. nullopt if no well-formed `header { ... }`
// is found within kMaxHeader of `base`.
inline std::optional<size_t> header_end(const Reader& r, size_t base) {
    const size_t limit = std::min(r.size(), base + kMaxHeader);
    auto span = r.bytes(base, limit - base);
    if (!span) return std::nullopt;
    const auto& d = *span;

    // Find the "header" keyword then its opening brace.
    static constexpr char kKw[] = "header";
    size_t hi = std::string::npos;
    for (size_t i = 0; i + 6 <= d.size(); ++i) {
        if (std::memcmp(d.data() + i, kKw, 6) == 0) { hi = i; break; }
    }
    if (hi == std::string::npos) return std::nullopt;

    size_t open = std::string::npos;
    for (size_t i = hi; i < d.size(); ++i)
        if (d[i] == '{') { open = i; break; }
    if (open == std::string::npos) return std::nullopt;

    int depth = 0;
    bool in_str = false, esc = false;
    for (size_t i = open; i < d.size(); ++i) {
        uint8_t c = d[i];
        if (in_str) {
            if (esc) { esc = false; continue; }
            if (c == '\\') { esc = true; continue; }
            if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') { in_str = true; continue; }
        if (c == '{') { ++depth; continue; }
        if (c == '}') {
            if (--depth == 0) return base + i + 1;  // one past the closing brace
        }
    }
    return std::nullopt;  // unbalanced within the cap
}

// Read the string value of `key` (as `key = <value>;`) from the header text in
// [base, end). Strips surrounding quotes. nullopt if the key is absent.
inline std::optional<std::string> field(const Reader& r, size_t base, size_t end,
                                        const std::string& key) {
    if (end <= base) return std::nullopt;
    auto span = r.bytes(base, end - base);
    if (!span) return std::nullopt;
    std::string text(reinterpret_cast<const char*>(span->data()), span->size());
    // Match `key` as a whole word followed by optional space, then '='.
    size_t pos = 0;
    while ((pos = text.find(key, pos)) != std::string::npos) {
        bool left_ok = (pos == 0) || !(isalnum((unsigned char)text[pos - 1]) || text[pos - 1] == '_');
        size_t after = pos + key.size();
        if (left_ok && after < text.size() &&
            !(isalnum((unsigned char)text[after]) || text[after] == '_')) {
            size_t eq = text.find('=', after);
            size_t semi = text.find(';', after);
            if (eq != std::string::npos && (semi == std::string::npos || eq < semi)) {
                std::string val = text.substr(eq + 1, (semi == std::string::npos ? text.size() : semi) - eq - 1);
                // trim whitespace
                size_t a = val.find_first_not_of(" \t\r\n");
                size_t b = val.find_last_not_of(" \t\r\n");
                if (a == std::string::npos) return std::string();
                val = val.substr(a, b - a + 1);
                if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                    val = val.substr(1, val.size() - 2);
                return val;
            }
        }
        pos = after;
    }
    return std::nullopt;
}

// data_format_identifier as a byte (0 if absent/unparseable). Compression is
// signalled by a non-zero upper nibble (0x10 == LZSS).
inline uint8_t data_format(const Reader& r, size_t base, size_t end) {
    auto v = field(r, base, end, "data_format_identifier");
    if (!v) return 0;
    const std::string& s = *v;
    int val = 0;
    if (s.size() > 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X')) {
        for (size_t i = 2; i < s.size(); ++i) {
            char c = s[i];
            int nib;
            if (c >= '0' && c <= '9') nib = c - '0';
            else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10;
            else break;
            val = (val << 4) | nib;
        }
    }
    return static_cast<uint8_t>(val & 0xFF);
}

inline bool is_compressed(uint8_t dfi) { return (dfi >> 4) != 0; }

}  // namespace vbf
}  // namespace ft

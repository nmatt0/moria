// wince_hive_parse.cpp — CE hive value recovery. See the header.
#include "wince_hive_parse.hpp"

#include <cstdio>

namespace ft {

namespace {

constexpr size_t kScanStart = 0x40;   // past the signature + header GUIDs
constexpr uint16_t kMaxNameChars = 64;
constexpr uint16_t kMaxDataLen = 0x4000;

// The registry types CE stores in a hive.
constexpr uint16_t kRegSz = 1;
constexpr uint16_t kRegExpandSz = 2;
constexpr uint16_t kRegBinary = 3;
constexpr uint16_t kRegDword = 4;
constexpr uint16_t kRegDwordBe = 5;
constexpr uint16_t kRegMultiSz = 7;
constexpr uint16_t kRegQword = 11;

bool known_type(uint16_t t) {
    return t == kRegSz || t == kRegExpandSz || t == kRegBinary || t == kRegDword ||
           t == kRegDwordBe || t == kRegMultiSz || t == kRegQword;
}

// The characters a real registry value name is made of. Anything outside this
// is how a coincidental length triple gets rejected.
bool name_char(char32_t c) {
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= 'a' && c <= 'z') return true;
    if (c >= '0' && c <= '9') return true;
    switch (c) {
        case '_': case '-': case '.': case ' ': case ':': case '\\': case '/': case '#':
        case '@': case '(': case ')': case '[': case ']': case '{': case '}': case '$':
        case '%': case '+': case '*': case '?': case '!': case ',': case '\'':
            return true;
        default:
            return false;
    }
}

void utf8_append(std::string& s, char32_t c) {
    if (c < 0x80) {
        s += static_cast<char>(c);
    } else if (c < 0x800) {
        s += static_cast<char>(0xC0 | (c >> 6));
        s += static_cast<char>(0x80 | (c & 0x3F));
    } else if (c < 0x10000) {
        s += static_cast<char>(0xE0 | (c >> 12));
        s += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (c & 0x3F));
    } else {
        s += static_cast<char>(0xF0 | (c >> 18));
        s += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
        s += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (c & 0x3F));
    }
}

// Decode UTF-16LE. `nul` chooses what an embedded NUL becomes: value strings
// are rendered with "|" between the members of a MULTI_SZ, names reject it.
bool utf16_to_utf8(std::span<const uint8_t> in, std::string& out, char nul) {
    for (size_t i = 0; i + 1 < in.size(); i += 2) {
        char32_t c = static_cast<char32_t>(in[i] | (uint32_t(in[i + 1]) << 8));
        if (c == 0) {
            if (!nul) return false;
            out += nul;
            continue;
        }
        if (c >= 0xD800 && c < 0xDC00 && i + 3 < in.size()) {  // surrogate pair
            const char32_t lo = static_cast<char32_t>(in[i + 2] | (uint32_t(in[i + 3]) << 8));
            if (lo >= 0xDC00 && lo < 0xE000) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            }
        }
        utf8_append(out, c);
    }
    return true;
}

std::string hex_of(std::span<const uint8_t> b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b) {
        s += d[c >> 4];
        s += d[c & 0xF];
    }
    return s;
}

// Render a value's bytes for the text dump: strings as text, the fixed-width
// integers as numbers, everything else as hex.
std::string render(uint16_t type, std::span<const uint8_t> data) {
    char buf[32];
    switch (type) {
        case kRegSz:
        case kRegExpandSz:
        case kRegMultiSz: {
            std::string s;
            utf16_to_utf8(data, s, '|');
            while (!s.empty() && s.back() == '|') s.pop_back();  // trailing terminators
            return s;
        }
        case kRegDword: {
            const uint32_t v = uint32_t(data[0]) | (uint32_t(data[1]) << 8) |
                               (uint32_t(data[2]) << 16) | (uint32_t(data[3]) << 24);
            std::snprintf(buf, sizeof(buf), "%u", v);
            return buf;
        }
        case kRegQword: {
            uint64_t v = 0;
            for (int i = 7; i >= 0; --i) v = (v << 8) | data[i];
            std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v));
            return buf;
        }
        default:
            return hex_of(data);
    }
}

}  // namespace

size_t ce_hive_values(const Reader& r, size_t base, std::vector<CeHiveValue>& out, size_t limit) {
    const size_t n = r.size();
    if (base + kScanStart + 6 > n) return 0;
    size_t found = 0;

    for (size_t i = base + kScanStart; i + 6 <= n && found < limit; i += 2) {
        const uint16_t type = r.at<uint16_t>(i, Endian::Little).value_or(0);
        if (!known_type(type)) continue;
        const uint16_t data_len = r.at<uint16_t>(i + 2, Endian::Little).value_or(0);
        const uint16_t name_len = r.at<uint16_t>(i + 4, Endian::Little).value_or(0);
        if (name_len == 0 || name_len > kMaxNameChars) continue;
        if (data_len == 0 || data_len > kMaxDataLen) continue;
        if (type == kRegDword && data_len != 4) continue;
        if (type == kRegDwordBe && data_len != 4) continue;
        if (type == kRegQword && data_len != 8) continue;

        auto name_raw = r.bytes(i + 6, size_t(name_len) * 2);
        if (!name_raw) continue;
        auto data = r.bytes(i + 6 + size_t(name_len) * 2, data_len);
        if (!data) continue;

        std::string name;
        if (!utf16_to_utf8(*name_raw, name, 0)) continue;  // an embedded NUL is not a name
        // A registry value name is ASCII in practice; anything else (including
        // a byte that only became valid UTF-8 by accident) is a false positive.
        bool ok = !name.empty();
        for (unsigned char c : name)
            if (!name_char(c)) {
                ok = false;
                break;
            }
        if (!ok) continue;

        out.push_back({i - base, std::move(name), type, render(type, *data)});
        ++found;
        // Deliberately no skip past the record: a false positive here must not
        // shift the scan away from the real records that follow it.
    }
    return found;
}

const char* ce_hive_type_name(uint16_t type) {
    switch (type) {
        case kRegSz: return "REG_SZ";
        case kRegExpandSz: return "REG_EXPAND_SZ";
        case kRegBinary: return "REG_BINARY";
        case kRegDword: return "REG_DWORD";
        case kRegDwordBe: return "REG_DWORD_BE";
        case kRegMultiSz: return "REG_MULTI_SZ";
        case kRegQword: return "REG_QWORD";
        default: return "";
    }
}

}  // namespace ft

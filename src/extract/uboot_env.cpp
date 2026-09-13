// uboot_env.cpp — U-Boot environment extraction. See uboot_env.hpp.
#include "extract/uboot_env.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {
constexpr size_t kMaxVars = 8192;  // sane cap on env entries

inline bool key_char(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '_';
}
}  // namespace

bool extract_uboot_env(const Reader& r, const Finding& f, SafeRoot& root,
                       const std::string& subdir, Extracted& out) {
    out.offset = f.offset;
    out.type = "uboot_env";
    out.root = subdir;

    std::span<const uint8_t> d = r.data();
    const size_t n = d.size();
    if (f.offset >= n) {
        out.status = "error:bad-offset";
        return true;
    }
    const size_t hlen = (f.label == "redundant") ? 5 : 4;
    size_t p = f.offset + hlen;
    // Structural findings assume a 4-byte header; if the block is actually
    // redundant, a flags byte (0x00/0x01/0xFF) precedes the first key. Skip it.
    if (p < n && !key_char(d[p]) && (d[p] == 0x00 || d[p] == 0x01 || d[p] == 0xFF)) ++p;

    const size_t end = (f.size && f.offset + f.size <= n) ? f.offset + f.size : n;

    std::string text;
    size_t vars = 0;
    while (p < end && vars < kMaxVars) {
        if (d[p] == 0x00) break;  // empty entry = end of the list
        size_t s = p;
        while (p < end && d[p] != 0x00) ++p;
        if (p >= end) break;  // unterminated
        text.append(reinterpret_cast<const char*>(d.data()) + s, p - s);
        text.push_back('\n');
        ++vars;
        ++p;  // step over the separator
    }
    if (vars == 0) {
        out.status = "error:no-vars";
        return true;
    }

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    std::vector<uint8_t> bytes(text.begin(), text.end());
    if (!root.write_file(subdir + "/uboot-env.txt", bytes, 0644)) {
        out.status = "error:write";
        return true;
    }
    out.files = 1;
    out.bytes = bytes.size();
    out.status = "ok";
    return true;
}

}  // namespace ft

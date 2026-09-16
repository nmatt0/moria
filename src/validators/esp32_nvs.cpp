// esp32_nvs.cpp — ESP-IDF NVS validator. See esp32_nvs.hpp.
//
// NVS has no format magic: a page starts with a state word (active 0xFFFFFFFE,
// full 0xFFFFFFFC, erasing 0xFFFFFFF8), which is what the signature anchors on.
// The validator is the filter: the page header must be well-formed (version
// byte, 0xFF padding) and CRC-verified, the entry-state bitmap must have its
// unused bits set, and every bitmap-written entry must pass its own CRC and
// span checks (a garbage bitmap or torn data fails here instead of producing a
// false positive). The finding spans the run of consistent pages; credential-
// looking keys (WiFi passwords, tokens, ...) are flagged as diagnostics.
#include "validators/esp32_nvs.hpp"

#include <cstdint>
#include <string>

#include "esp32_nvs_parse.hpp"

namespace ft {

bool validate_esp32_nvs(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;
    if (!nvs_page_valid(r, off)) return false;
    // The bitmap's last 4 bits (entries 126/127 do not exist) stay 0b11.
    auto bm_tail = r.at<uint8_t>(off + 32 + 31, Endian::Little);
    if (!bm_tail || (*bm_tail & 0xF0) != 0xF0) return false;

    NvsParse p = nvs_parse(r, off);
    if (!p.ok || p.bad_entries > 0) return false;

    Finding& out = ctx.out;
    out.type = "esp32_nvs";
    out.category = "container";
    out.endian = Endian::Little;
    out.size = p.extent;

    size_t flagged = 0;
    for (const auto& v : p.values) {
        if (!v.sensitive || flagged >= 32) continue;
        ++flagged;
        out.diagnostics.push_back({"warning", "esp32-nvs-sensitive-key",
                                   "key '" + v.ns + ":" + v.key +
                                       "' matches a credential pattern"});
    }

    out.set_confidence(Confidence::Verified,
                       "NVS page CRC32 verified: " + std::to_string(p.pages_valid) +
                           (p.pages_valid == 1 ? " page, " : " pages, ") +
                           std::to_string(p.keys) + (p.keys == 1 ? " key" : " keys"));
    return true;
}

}  // namespace ft

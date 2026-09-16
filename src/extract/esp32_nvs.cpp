// esp32_nvs.cpp — ESP-IDF NVS extraction. See esp32_nvs.hpp.
#include "extract/esp32_nvs.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "esp32_nvs_parse.hpp"
#include "extract/safepath.hpp"

namespace ft {

bool extract_esp32_nvs(const Reader& r, const Finding& f, SafeRoot& root,
                       const std::string& subdir, Extracted& out) {
    out.offset = f.offset;
    out.type = "esp32_nvs";
    out.root = subdir;

    NvsParse p = nvs_parse(r, f.offset);
    if (!p.ok) {
        out.status = "error:bad-page";
        return true;
    }
    if (p.keys == 0) {
        out.status = "error:no-keys";
        return true;
    }

    std::string text;
    char hdr[160];
    std::snprintf(hdr, sizeof(hdr),
                  "# esp32_nvs @ 0x%zx: %zu valid page(s), %zu erased page(s), %zu key(s)\n",
                  f.offset, p.pages_valid, p.pages_erased, p.keys);
    text += hdr;
    bool any_sensitive = false;
    for (const auto& v : p.values) any_sensitive = any_sensitive || v.sensitive;
    if (any_sensitive) {
        text += "# sensitive keys:";
        for (const auto& v : p.values)
            if (v.sensitive) text += " " + v.ns + ":" + v.key;
        text += "\n";
    }
    for (const auto& w : p.warnings) text += "# warning: " + w + "\n";

    for (const auto& v : p.values) {
        const char* tn = nvs_type_name(v.type);
        char tbuf[8];
        if (!tn) {
            std::snprintf(tbuf, sizeof(tbuf), "0x%02x", v.type);
            tn = tbuf;
        }
        text += v.ns + ":" + v.key + " = " + v.text + " ; " + tn + "\n";
    }

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    std::vector<uint8_t> bytes(text.begin(), text.end());
    if (!root.write_file(subdir + "/nvs-values.txt", bytes, 0644)) {
        out.status = "error:write";
        return true;
    }
    out.files = 1;
    out.bytes = bytes.size();
    out.status = (p.bad_entries > 0 || !p.warnings.empty()) ? "partial" : "ok";
    return true;
}

}  // namespace ft

// esp32_nvs.cpp — ESP-IDF NVS extraction. See esp32_nvs.hpp.
#include "extract/esp32_nvs.hpp"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "esp32_nvs_parse.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {
// Filesystem-safe token from a namespace/key (for blob filenames).
std::string safe_tok(const std::string& s) {
    std::string o;
    for (char c : s) o.push_back(std::isalnum(static_cast<unsigned char>(c)) ? c : '_');
    return o.empty() ? "_" : o;
}
}  // namespace

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

    // Write each non-empty blob's full bytes to a file, so a recovered PEM key /
    // cert / binary value survives intact (nvs-values.txt only holds a preview).
    size_t blob_files = 0, sensitive = 0;
    bool blobdir = false;
    for (const auto& v : p.values) {
        if (v.sensitive) ++sensitive;
        if (v.raw.empty()) continue;
        if (!blobdir) {
            root.make_dir(subdir + "/blobs");
            blobdir = true;
        }
        std::string rel =
            subdir + "/blobs/" + safe_tok(v.ns) + "." + safe_tok(v.key) + ".bin";
        if (root.write_file(rel, v.raw, 0644)) {
            ++blob_files;
            out.bytes += v.raw.size();
        }
    }
    out.files += blob_files;
    if (sensitive)
        out.warnings.push_back(std::to_string(sensitive) + " sensitive key(s) (WiFi/creds/keys)");

    out.status = (p.bad_entries > 0 || !p.warnings.empty()) ? "partial" : "ok";
    return true;
}

}  // namespace ft

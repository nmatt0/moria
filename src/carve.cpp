// carve.cpp — see carve.hpp.
#include "carve.hpp"

#include <algorithm>
#include <cstdio>
#include <set>
#include <string>

#include "assess.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

// Minimum unidentified-gap size to carve by default; below this a gap is almost
// always padding/alignment, not worth a standalone blob. `-A` lowers it to 1.
constexpr size_t kMinGap = 1024;

// A single span to carve, in offset order.
struct Item {
    size_t offset;
    size_t size;
    std::string label;  // finding type, or "unknown" for a gap
};

// Filename-safe rendering of a type token (types are simple, but be defensive).
std::string safe_label(const std::string& s) {
    std::string out;
    for (char c : s) {
        unsigned char u = static_cast<unsigned char>(c);
        bool ok = (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') || (u >= '0' && u <= '9') ||
                  c == '_' || c == '-' || c == '.';
        out += ok ? c : '_';
    }
    if (out.empty()) out = "region";
    return out;
}

// Zero-padded hex offset, width chosen so names sort lexically by offset.
std::string off_name(size_t off, int width) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%0*zx", width, off);
    return buf;
}

// Minimal manifest so a carve run is self-describing.
std::string manifest_json(const std::string& src, const std::vector<Item>& items,
                          const std::vector<std::string>& names) {
    auto esc = [](const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '"' || c == '\\') o += '\\', o += c;
            else if (c == '\n') o += "\\n";
            else o += c;
        }
        return o;
    };
    std::string j = "{\n  \"source\": \"" + esc(src) + "\",\n  \"carved\": [\n";
    for (size_t i = 0; i < items.size(); ++i) {
        char n[64];
        std::snprintf(n, sizeof(n), "\"offset\": %zu, \"size\": %zu", items[i].offset, items[i].size);
        j += "    { \"file\": \"" + esc(names[i]) + "\", " + n + ", \"type\": \"" +
             esc(items[i].label) + "\" }";
        j += (i + 1 < items.size()) ? ",\n" : "\n";
    }
    j += "  ]\n}\n";
    return j;
}

}  // namespace

CarveResult carve(const std::string& src_path, const Reader& reader,
                  const std::vector<Finding>& findings, const std::string& outdir, bool all,
                  uint64_t max_bytes) {
    CarveResult res;
    const size_t fsize = reader.size();

    std::vector<Item> items;
    for (const auto& f : findings) {
        if (f.size == 0) {  // unknown extent — nothing definite to carve
            ++res.skipped_unknown;
            continue;
        }
        if (f.offset >= fsize) continue;
        size_t sz = std::min(f.size, fsize - f.offset);  // never read past EOF
        items.push_back({f.offset, sz, safe_label(f.type)});
    }

    // Unidentified gaps between findings. `all` carves every gap; default skips
    // sub-kilobyte padding.
    for (const auto& r : unidentified_regions(reader, findings, all ? 1 : kMinGap))
        items.push_back({r.offset, r.size, "unknown"});

    if (items.empty()) return res;

    std::sort(items.begin(), items.end(),
              [](const Item& a, const Item& b) { return a.offset < b.offset; });

    SafeRoot root;
    if (!root.open(outdir)) {
        std::fprintf(stderr, "error: cannot create carve dir: %s\n", outdir.c_str());
        return res;
    }
    res.outdir = root.path();

    int width = 1;
    for (size_t v = fsize; v >= 16; v /= 16) ++width;

    std::set<std::string> used;
    std::vector<std::string> names;
    std::vector<Item> written;
    for (const auto& it : items) {
        if (res.bytes_written + it.size > max_bytes) {
            res.capped = true;
            break;
        }
        auto span = reader.bytes(it.offset, it.size);
        if (!span) continue;  // bounds already clamped; defensive

        std::string base = off_name(it.offset, width) + "-" + it.label;
        std::string name = base + ".bin";
        for (int n = 2; used.count(name); ++n) name = base + "-" + std::to_string(n) + ".bin";
        used.insert(name);

        std::vector<uint8_t> data(span->begin(), span->end());
        if (!root.write_file(name, data, 0644)) continue;
        names.push_back(name);
        written.push_back(it);
        ++res.regions_written;
        res.bytes_written += it.size;
    }

    if (!written.empty()) {
        std::string j = manifest_json(src_path, written, names);
        std::vector<uint8_t> mb(j.begin(), j.end());
        root.write_file("manifest.json", mb, 0644);
    }
    return res;
}

}  // namespace ft

// wince_hive.cpp — Windows CE registry hive value dump. See the header.
#include "extract/wince_hive.hpp"

#include <cstdio>
#include <vector>

#include "extract/safepath.hpp"
#include "wince_hive_parse.hpp"

namespace ft {

namespace {
constexpr size_t kMaxValues = 500000;  // a bound on adversarial input, not on real hives

// Keep a value on one line: control characters would break the dump's shape.
std::string one_line(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u == '\t') o += "\\t";
        else if (u == '\r') o += "\\r";
        else if (u == '\n') o += "\\n";
        else if (u < 0x20 || u == 0x7f) o += '.';
        else o += c;
    }
    return o;
}
}  // namespace

bool extract_wince_hive(const Reader& r, const Finding& f, SafeRoot& root,
                        const std::string& subdir, Extracted& out) {
    out.offset = f.offset;
    out.type = "wince_hive";
    out.root = subdir;

    std::vector<CeHiveValue> values;
    ce_hive_values(r, f.offset, values, kMaxValues);
    if (values.empty()) {
        out.status = "error:no-values";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    std::string text =
        "# Windows CE registry values recovered from the hive at offset " +
        std::to_string(f.offset) + ".\n"
        "# Recovered record by record: CE's cell layout is not walked, so these\n"
        "# values carry no key path. Columns: hive offset, name, type, value.\n";
    char off[24];
    for (const CeHiveValue& v : values) {
        std::snprintf(off, sizeof(off), "0x%08zx", v.offset);
        text += off;
        text += "  ";
        text += v.name;
        text.append(v.name.size() < 40 ? 40 - v.name.size() : 1, ' ');
        const char* tn = ce_hive_type_name(v.type);
        text += tn;
        const size_t tl = std::char_traits<char>::length(tn);
        text.append(tl < 15 ? 15 - tl : 1, ' ');
        text += one_line(v.rendered);
        text += '\n';
    }

    const std::vector<uint8_t> bytes(text.begin(), text.end());
    if (!root.write_file(subdir + "/registry-values.txt", bytes, 0644)) {
        out.status = "error:write";
        return true;
    }
    out.files = 1;
    out.bytes = bytes.size();
    out.consumed = r.size() - f.offset;
    out.status = values.size() >= kMaxValues ? "partial" : "ok";
    if (values.size() >= kMaxValues)
        out.warnings.push_back("value recovery stopped at the " + std::to_string(kMaxValues) +
                               "-record cap");
    return true;
}

}  // namespace ft

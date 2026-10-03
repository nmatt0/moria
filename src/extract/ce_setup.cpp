// ce_setup.cpp — _setup.xml parsing and install-path expansion. See the header.
//
// The document is machine-generated and shallow, so this walks it with a small
// tag scanner and a stack of the `type` attributes rather than pulling in an
// XML library: the structure being read is "which nested characteristic types
// enclose this Extract", which is exactly a stack of names.
#include "extract/ce_setup.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace ft {

namespace {

// CE special-directory macros used in _setup.xml destination paths.
struct Macro {
    const char* macro;
    const char* path;
};
constexpr Macro kCeDirs[] = {
    {"%CE1%", "\\Program Files"},
    {"%CE2%", "\\Windows"},
    {"%CE3%", "\\Windows\\Desktop"},
    {"%CE4%", "\\Windows\\StartUp"},
    {"%CE5%", "\\My Documents"},
    {"%CE6%", "\\Program Files\\Accessories"},
    {"%CE7%", "\\Program Files\\Communications"},
    {"%CE8%", "\\Program Files\\Games"},
    {"%CE9%", "\\Program Files\\Pocket Outlook"},
    {"%CE10%", "\\Program Files\\Office"},
    {"%CE11%", "\\Windows\\Start Menu\\Programs"},
    {"%CE12%", "\\Windows\\Start Menu\\Accessories"},
    {"%CE13%", "\\Windows\\Start Menu\\Communications"},
    {"%CE14%", "\\Windows\\Start Menu\\Programs\\Games"},
    {"%CE15%", "\\Windows\\Fonts"},
    {"%CE16%", "\\Windows\\Recent"},
    {"%CE17%", "\\Windows\\Start Menu"},
};

std::string replace_all(std::string s, const std::string& from, const std::string& to) {
    if (from.empty()) return s;
    for (size_t p = s.find(from); p != std::string::npos; p = s.find(from, p + to.size()))
        s.replace(p, from.size(), to);
    return s;
}

// Expand CE macros and normalise to a relative POSIX path with no traversal.
std::string ce_path(std::string p) {
    for (const Macro& m : kCeDirs) p = replace_all(std::move(p), m.macro, m.path);
    p = replace_all(std::move(p), "%InstallDir%", "InstallDir");
    for (char& c : p)
        if (c == '\\') c = '/';
    std::string out;
    size_t i = 0;
    while (i < p.size()) {
        size_t j = p.find('/', i);
        if (j == std::string::npos) j = p.size();
        std::string part = p.substr(i, j - i);
        i = j + 1;
        if (part.empty() || part == "." || part == "..") continue;
        // Anything still carrying a macro (%CE99%, %AppName%) would make an odd
        // directory name; keep it readable but harmless.
        for (char& c : part) {
            const unsigned char u = static_cast<unsigned char>(c);
            if (u < 0x20 || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' ||
                c == '|')
                c = '_';
        }
        if (!out.empty()) out += '/';
        out += part;
    }
    return out;
}

std::string decode_entities(const std::string& s) {
    if (s.find('&') == std::string::npos) return s;
    std::string o;
    o.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        if (s[i] != '&') {
            o += s[i++];
            continue;
        }
        const size_t semi = s.find(';', i);
        if (semi == std::string::npos || semi - i > 10) {
            o += s[i++];
            continue;
        }
        const std::string ent = s.substr(i + 1, semi - i - 1);
        if (ent == "amp") o += '&';
        else if (ent == "lt") o += '<';
        else if (ent == "gt") o += '>';
        else if (ent == "quot") o += '"';
        else if (ent == "apos") o += '\'';
        else if (ent.size() > 1 && ent[0] == '#') {
            const long v = std::strtol(ent.c_str() + (ent[1] == 'x' || ent[1] == 'X' ? 2 : 1),
                                       nullptr, (ent[1] == 'x' || ent[1] == 'X') ? 16 : 10);
            if (v > 0 && v < 0x80) o += static_cast<char>(v);
            // Non-ASCII character references are left out rather than guessed at.
        } else {
            o += s.substr(i, semi - i + 1);  // unknown entity: keep it verbatim
        }
        i = semi + 1;
    }
    return o;
}

struct Tag {
    std::string name;
    std::vector<std::pair<std::string, std::string>> attrs;
    bool closing = false;
    bool self_closing = false;
};

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

// Scan the next element starting at or after `i`. False at end of document.
bool next_tag(const std::string& s, size_t& i, Tag& t) {
    for (;;) {
        const size_t lt = s.find('<', i);
        if (lt == std::string::npos) return false;
        size_t p = lt + 1;
        if (p < s.size() && (s[p] == '!' || s[p] == '?')) {  // comment / PI / doctype
            const size_t gt = s.find('>', p);
            if (gt == std::string::npos) return false;
            i = gt + 1;
            continue;
        }
        t = Tag{};
        if (p < s.size() && s[p] == '/') {
            t.closing = true;
            ++p;
        }
        const size_t ns = p;
        while (p < s.size() && !is_space(s[p]) && s[p] != '>' && s[p] != '/') ++p;
        t.name = s.substr(ns, p - ns);

        while (p < s.size()) {
            while (p < s.size() && is_space(s[p])) ++p;
            if (p >= s.size()) return false;
            if (s[p] == '/') {
                t.self_closing = true;
                ++p;
                continue;
            }
            if (s[p] == '>') {
                i = p + 1;
                return !t.name.empty();
            }
            const size_t as = p;
            while (p < s.size() && !is_space(s[p]) && s[p] != '=' && s[p] != '>' && s[p] != '/')
                ++p;
            const std::string key = s.substr(as, p - as);
            std::string val;
            while (p < s.size() && is_space(s[p])) ++p;
            if (p < s.size() && s[p] == '=') {
                ++p;
                while (p < s.size() && is_space(s[p])) ++p;
                if (p < s.size() && (s[p] == '"' || s[p] == '\'')) {
                    const char q = s[p++];
                    const size_t vs = p;
                    while (p < s.size() && s[p] != q) ++p;
                    val = decode_entities(s.substr(vs, p - vs));
                    if (p < s.size()) ++p;
                }
            }
            if (!key.empty()) t.attrs.emplace_back(key, std::move(val));
        }
        return false;
    }
}

const std::string* attr(const Tag& t, const char* name) {
    for (const auto& a : t.attrs)
        if (a.first == name) return &a.second;
    return nullptr;
}

std::string join(const std::vector<std::string>& parts, size_t from, size_t to, char sep) {
    std::string o;
    for (size_t i = from; i < to; ++i) {
        if (!o.empty()) o += sep;
        o += parts[i];
    }
    return o;
}

}  // namespace

bool ce_setup_parse(std::span<const uint8_t> xml, CeSetup& out) {
    const std::string s(reinterpret_cast<const char*>(xml.data()), xml.size());
    size_t i = 0;
    Tag t;

    // Stack of enclosing <characteristic type="..."> values. Its first element
    // names the section (Install / FileOperation / Registry); the rest spell out
    // either an install path or a registry key.
    std::vector<std::string> stack;
    bool saw_section = false;

    while (next_tag(s, i, t)) {
        if (t.name == "characteristic") {
            if (t.closing) {
                if (!stack.empty()) stack.pop_back();
                continue;
            }
            const std::string* ty = attr(t, "type");
            stack.push_back(ty ? *ty : std::string());
            if (stack.size() == 1) saw_section = true;

            // A registry key element is the key itself; record it now so keys
            // with no values still appear.
            if (stack.size() >= 2 && stack[0] == "Registry")
                out.registry.push_back({join(stack, 1, stack.size(), '\\'), {}});

            if (t.self_closing && !stack.empty()) stack.pop_back();
            continue;
        }
        if (t.name != "parm" || t.closing || stack.empty()) continue;

        const std::string* nm = attr(t, "name");
        const std::string* val = attr(t, "value");
        if (!nm) continue;

        if (stack[0] == "Install") {
            if (*nm == "AppName" && val) out.appname = *val;
        } else if (stack[0] == "FileOperation") {
            // <parm name="Source"> inside an Extract: everything between the
            // section and the Extract is the destination path.
            if (*nm == "Source" && val && stack.back() == "Extract" && stack.size() >= 3) {
                CeSetupEntry e;
                e.source = *val;
                e.dest = ce_path(join(stack, 1, stack.size() - 1, '/'));
                if (!e.source.empty() && !e.dest.empty()) out.files.push_back(std::move(e));
            }
        } else if (stack[0] == "Registry") {
            if (!out.registry.empty())
                out.registry.back().values.push_back(
                    {*nm, val ? *val : std::string(),
                     attr(t, "datatype") ? *attr(t, "datatype") : std::string()});
        }
    }
    // Drop registry keys that carried no values (pure path elements).
    out.registry.erase(std::remove_if(out.registry.begin(), out.registry.end(),
                                      [](const CeRegKey& k) { return k.values.empty(); }),
                       out.registry.end());
    return saw_section;
}

std::string ce_setup_reg_file(const std::vector<CeRegKey>& keys) {
    struct Hive {
        const char* abbrev;
        const char* full;
    };
    constexpr Hive kHives[] = {
        {"HKLM", "HKEY_LOCAL_MACHINE"},
        {"HKCU", "HKEY_CURRENT_USER"},
        {"HKCR", "HKEY_CLASSES_ROOT"},
        {"HKU", "HKEY_USERS"},
    };

    std::string o = "Windows Registry Editor Version 5.00\n\n";
    for (const CeRegKey& k : keys) {
        const size_t sep = k.key.find('\\');
        const std::string head = sep == std::string::npos ? k.key : k.key.substr(0, sep);
        const std::string rest = sep == std::string::npos ? std::string() : k.key.substr(sep + 1);
        std::string full;
        for (const Hive& h : kHives)
            if (head == h.abbrev) {
                full = h.full;
                if (!rest.empty()) full += "\\" + rest;
                break;
            }
        // CE setup docs normally carry their own hive prefix; anything else is
        // a machine key by convention.
        if (full.empty()) full = std::string("HKEY_LOCAL_MACHINE\\") + k.key;

        o += "[" + full + "]\n";
        for (const CeRegValue& v : k.values) {
            if (v.name.empty()) continue;
            if (v.datatype == "integer") {
                char* end = nullptr;
                const long n = std::strtol(v.value.c_str(), &end, 10);
                if (end && *end == '\0' && !v.value.empty()) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "%08lx", static_cast<unsigned long>(n));
                    o += "\"" + v.name + "\"=dword:" + buf + "\n";
                    continue;
                }
            }
            std::string esc;
            for (char c : v.value) {
                if (c == '\\' || c == '"') esc += '\\';
                esc += c;
            }
            o += "\"" + v.name + "\"=\"" + esc + "\"\n";
        }
        o += "\n";
    }
    return o;
}

}  // namespace ft

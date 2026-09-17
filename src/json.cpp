#include "json.hpp"

#include <cstdio>
#include <utility>

#include "mime.hpp"

namespace ft {

// Output JSON schema version. Bump on any breaking change to field names/shapes.
constexpr int FT_SCHEMA_VERSION = 1;

namespace {

void escape_to(std::string& out, const std::string& s) {
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: {
                unsigned char uc = static_cast<unsigned char>(c);
                // Escape control bytes and any non-ASCII byte so the output is
                // always valid JSON/UTF-8, even when a field (e.g. a uImage
                // name) carries raw binary. High bytes map to \u00XX.
                if (uc < 0x20 || uc >= 0x80) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", uc);
                    out += buf;
                } else {
                    out += c;
                }
            }
        }
    }
}

void kv_str(std::string& o, const char* key, const std::string& val, bool& first) {
    if (!first) o += ",";
    first = false;
    o += "\"";
    o += key;
    o += "\":\"";
    escape_to(o, val);
    o += "\"";
}

void kv_num(std::string& o, const char* key, unsigned long long val, bool& first) {
    if (!first) o += ",";
    first = false;
    o += "\"";
    o += key;
    o += "\":";
    o += std::to_string(val);
}

// A double with 2 decimals (for the -E entropy field).
void kv_double(std::string& o, const char* key, double val, bool& first) {
    if (!first) o += ",";
    first = false;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "\"%s\":%.2f", key, val);
    o += buf;
}

void emit_finding(std::string& o, const Finding& f, bool with_also_matched);

void emit_finding(std::string& o, const Finding& f, bool with_also_matched) {
    o += "{";
    bool first = true;
    kv_num(o, "offset", f.offset, first);
    kv_num(o, "size", f.size, first);
    kv_str(o, "type", f.type, first);
    kv_str(o, "category", f.category, first);
    kv_str(o, "mime", mime_for_type(f.type), first);
    kv_num(o, "confidence", f.confidence, first);
    kv_str(o, "confidence_tier", f.confidence_tier, first);
    if (f.coalesced_count > 1) kv_num(o, "coalesced_count", f.coalesced_count, first);
    kv_str(o, "endian", endian_name(f.endian), first);
    if (!f.version.empty()) kv_str(o, "version", f.version, first);
    if (!f.label.empty()) kv_str(o, "label", f.label, first);
    if (!f.compression.empty()) kv_str(o, "compression", f.compression, first);
    if (!f.arch.empty()) kv_str(o, "arch", f.arch, first);
    if (f.entropy >= 0) kv_double(o, "entropy", f.entropy, first);

    // Archive members (from --list) — emitted even in compact mode (the point of --list).
    if (!f.members.empty()) {
        o += ",\"members\":[";
        for (size_t i = 0; i < f.members.size(); ++i) {
            if (i) o += ",";
            o += "{\"name\":\"";
            escape_to(o, f.members[i].name);
            o += "\",\"size\":" + std::to_string(f.members[i].size);
            if (f.members[i].offset != SIZE_MAX)
                o += ",\"offset\":" + std::to_string(f.members[i].offset);
            if (f.members[i].entropy >= 0) {
                char eb[32];
                std::snprintf(eb, sizeof(eb), ",\"entropy\":%.2f", f.members[i].entropy);
                o += eb;
            }
            if (!f.members[i].note.empty()) {
                o += ",\"note\":\"";
                escape_to(o, f.members[i].note);
                o += "\"";
            }
            if (!f.members[i].children.empty()) {
                o += ",\"findings\":[";
                for (size_t k = 0; k < f.members[i].children.size(); ++k) {
                    if (k) o += ",";
                    emit_finding(o, f.members[i].children[k], false);
                }
                o += "]";
            }
            o += "}";
        }
        o += "]";
        if (f.members_truncated) o += ",\"members_truncated\":true";
    }

    kv_str(o, "evidence", f.evidence, first);
    kv_str(o, "description", f.description, first);
    if (!f.vendor.empty()) kv_str(o, "vendor", f.vendor, first);

    // references: array of {title,url}
    if (!first) o += ",";
    first = false;
    o += "\"references\":[";
    for (size_t i = 0; i < f.references.size(); ++i) {
        if (i) o += ",";
        o += "{\"title\":\"";
        escape_to(o, f.references[i].title);
        o += "\",\"url\":\"";
        escape_to(o, f.references[i].url);
        o += "\"}";
    }
    o += "]";

    // limitations: array of strings
    o += ",\"limitations\":[";
    for (size_t i = 0; i < f.limitations.size(); ++i) {
        if (i) o += ",";
        o += "\"";
        escape_to(o, f.limitations[i]);
        o += "\"";
    }
    o += "]";

    // diagnostics: array of {severity,code,message} about this finding.
    if (!f.diagnostics.empty()) {
        o += ",\"diagnostics\":[";
        for (size_t i = 0; i < f.diagnostics.size(); ++i) {
            if (i) o += ",";
            o += "{\"severity\":\"";
            escape_to(o, f.diagnostics[i].severity);
            o += "\",\"code\":\"";
            escape_to(o, f.diagnostics[i].code);
            o += "\",\"message\":\"";
            escape_to(o, f.diagnostics[i].message);
            o += "\"}";
        }
        o += "]";
    }

    // Weaker signatures suppressed at/inside this finding (flat, not recursive).
    if (with_also_matched && !f.also_matched.empty()) {
        o += ",\"also_matched\":[";
        for (size_t i = 0; i < f.also_matched.size(); ++i) {
            if (i) o += ",";
            emit_finding(o, f.also_matched[i], false);
        }
        o += "]";
    }

    o += "}";
}

std::string make_summary(const std::vector<Finding>& findings) {
    if (findings.empty()) return "no known signatures identified";
    // Count by type, preserving first-seen order of appearance.
    std::vector<std::pair<std::string, int>> counts;
    for (const auto& f : findings) {
        bool found = false;
        for (auto& c : counts)
            if (c.first == f.type) {
                c.second++;
                found = true;
                break;
            }
        if (!found) counts.push_back({f.type, 1});
    }
    std::string s;
    for (size_t i = 0; i < counts.size(); ++i) {
        if (i) s += ", ";
        s += counts[i].first;
        if (counts[i].second > 1) s += " x" + std::to_string(counts[i].second);
    }
    return s;
}

}  // namespace

namespace {
void emit_regions(std::string& o, const std::vector<Region>& regions) {
    o += ",\"unidentified_regions\":[";
    for (size_t i = 0; i < regions.size(); ++i) {
        if (i) o += ",";
        char ent[16];
        std::snprintf(ent, sizeof(ent), "%.2f", regions[i].entropy);
        o += "{\"offset\":" + std::to_string(regions[i].offset) +
             ",\"size\":" + std::to_string(regions[i].size) + ",\"entropy\":" + ent + "}";
    }
    o += "]";
}

// Top-level `diagnostics`: the union of every finding's diagnostics, each
// enriched with the finding's offset and type so a consumer has one array to
// check. Per-finding diagnostics also stay on their finding object.
void emit_diagnostics_union(std::string& o, const std::vector<Finding>& findings) {
    bool any = false;
    for (const auto& f : findings)
        if (!f.diagnostics.empty()) { any = true; break; }
    if (!any) return;
    o += ",\"diagnostics\":[";
    bool first = true;
    for (const auto& f : findings) {
        for (const auto& d : f.diagnostics) {
            if (!first) o += ",";
            first = false;
            o += "{\"severity\":\"";
            escape_to(o, d.severity);
            o += "\",\"code\":\"";
            escape_to(o, d.code);
            o += "\",\"offset\":" + std::to_string(f.offset);
            o += ",\"type\":\"";
            escape_to(o, f.type);
            o += "\",\"message\":\"";
            escape_to(o, d.message);
            o += "\"}";
        }
    }
    o += "]";
}

// `regions`/`assessment` are emitted only for the top-level single-file object
// (nullptr from per-file tree entries).
void emit_file_obj(std::string& o, const std::string& path, size_t file_size,
                   const std::vector<Finding>& findings, const std::vector<Region>* regions,
                   const std::string* assessment, bool top_level) {
    o += "{";
    bool first = true;
    if (top_level) kv_num(o, "schema_version", FT_SCHEMA_VERSION, first);
    kv_str(o, "path", path, first);
    kv_num(o, "size", file_size, first);
    kv_str(o, "summary", make_summary(findings), first);
    if (assessment) kv_str(o, "assessment", *assessment, first);
    o += ",\"findings\":[";
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i) o += ",";
        emit_finding(o, findings[i], true);
    }
    o += "]";
    if (top_level) emit_diagnostics_union(o, findings);
    if (regions) emit_regions(o, *regions);
    o += "}";
}
}  // namespace

std::string emit_file_json(const std::string& path, size_t file_size,
                           const std::vector<Finding>& findings,
                           const std::vector<Region>& regions, const std::string& assessment,
                           const std::string& extraction) {
    std::string o;
    emit_file_obj(o, path, file_size, findings, &regions, &assessment, true);
    // Splice the extraction manifest (an object of its own) in before the close.
    if (!extraction.empty() && !o.empty() && o.back() == '}') {
        o.pop_back();
        o += ",\"extraction\":" + extraction + "}";
    }
    return o;
}

// Streaming tree JSON: the `files` array is written incrementally so the scan
// never holds every file's findings at once (G7). The object opens with the
// preamble + `"files":[`, each file object is appended as it is scanned, then the
// trailer closes the array and appends the aggregates. Key order differs from a
// buffered object (files precede the aggregates), which JSON consumers ignore.
std::string emit_tree_json_head(const std::string& root) {
    std::string o = "{";
    bool first = true;
    kv_num(o, "schema_version", FT_SCHEMA_VERSION, first);
    kv_str(o, "root", root, first);
    o += ",\"files\":[";
    return o;
}

// One file object for the streamed `files` array. `index` is its position so the
// caller need not track the comma separator.
std::string emit_tree_file(const FileResult& fr, size_t index) {
    std::string o;
    if (index) o += ",";
    emit_file_obj(o, fr.path, fr.size, fr.findings, nullptr, nullptr, false);
    return o;
}

std::string emit_tree_json_tail(const TreeResult& tr, const std::string& assessment) {
    std::string o = "]";  // close the files array
    bool first = false;   // preamble already wrote keys, so always prefix a comma
    kv_num(o, "file_count", tr.file_count, first);
    kv_str(o, "assessment", assessment, first);

    o += ",\"by_type\":{";
    for (size_t i = 0; i < tr.by_type.size(); ++i) {
        if (i) o += ",";
        o += "\"";
        escape_to(o, tr.by_type[i].first);
        o += "\":";
        o += std::to_string(tr.by_type[i].second);
    }
    o += "}";

    o += ",\"notable\":[";
    for (size_t i = 0; i < tr.notable.size(); ++i) {
        if (i) o += ",";
        o += "{\"path\":\"";
        escape_to(o, tr.notable[i].path);
        o += "\",\"finding\":";
        emit_finding(o, tr.notable[i].finding, false);
        o += "}";
    }
    o += "]";

    o += "}";
    return o;
}

}  // namespace ft

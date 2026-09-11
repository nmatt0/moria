// human.cpp — human-readable rendering. See human.hpp.
#include "human.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace ft {

namespace {

// ANSI helpers (no-ops when color is off).
struct Palette {
    bool on;
    const char* dim() const { return on ? "\033[2m" : ""; }
    const char* bold() const { return on ? "\033[1m" : ""; }
    const char* reset() const { return on ? "\033[0m" : ""; }
    const char* tier(const std::string& t) const {
        if (!on) return "";
        if (t == "verified") return "\033[32m";    // green
        if (t == "consistent") return "\033[36m";  // cyan
        if (t == "structural") return "\033[33m";  // yellow
        return "\033[2m";                          // magic / other: faint
    }
    const char* off() const { return on ? "\033[35m" : ""; }  // magenta offsets
    // Red = security-sensitive (act on it): a private key. A certificate is a
    // public artifact, not a finding to act on.
    const char* sec(const Finding& f) const {
        if (!on) return "";
        if (f.type == "private_key") return "\033[31m";  // red
        return "";
    }
    const char* sev(const std::string& s) const {
        if (!on) return "";
        if (s == "error") return "\033[31m";    // red
        if (s == "warning") return "\033[33m";   // yellow
        return "\033[2m";                        // info: faint
    }
};

std::string human_size(size_t n) {
    static const std::array<const char*, 5> unit{"B", "KB", "MB", "GB", "TB"};
    double v = static_cast<double>(n);
    size_t u = 0;
    while (v >= 1024.0 && u + 1 < unit.size()) {
        v /= 1024.0;
        ++u;
    }
    char buf[32];
    if (u == 0)
        std::snprintf(buf, sizeof(buf), "%zu B", n);
    else if (v >= 100)
        std::snprintf(buf, sizeof(buf), "%.0f %s", v, unit[u]);
    else
        std::snprintf(buf, sizeof(buf), "%.1f %s", v, unit[u]);
    return buf;
}

std::string hex_off(size_t o) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%zx", o);
    return buf;
}

// Printable, length-capped, control-stripped rendering of an embedded label.
std::string clean_label(const std::string& s, size_t cap = 40) {
    std::string out;
    for (char c : s) {
        unsigned char u = static_cast<unsigned char>(c);
        out += (u >= 0x20 && u < 0x7f) ? c : '.';
        if (out.size() >= cap) {
            out += "…";  // ellipsis
            break;
        }
    }
    return out;
}

// Compact "notes" column: endianness, arch, version, compression, label, etc.
// The caller renders the whole string dim; diagnostic tags are re-colored by
// severity (a warning is yellow) so they catch the eye down the NOTES column
// while the rest stays faint. Tags come last, so the color escapes don't bleed.
std::string notes_for(const Finding& f, const Palette& p) {
    std::vector<std::string> parts;
    std::string ev = endian_name(f.endian);
    if (!f.arch.empty()) ev += "/" + f.arch;
    parts.push_back(ev);
    if (!f.version.empty()) parts.push_back("v" + f.version);
    if (!f.compression.empty()) parts.push_back(f.compression);
    if (f.coalesced_count > 1) parts.push_back("x" + std::to_string(f.coalesced_count));
    if (!f.members.empty())
        parts.push_back(std::to_string(f.members.size()) + (f.members_truncated ? "+ members" : " members"));
    std::string s;
    for (size_t i = 0; i < parts.size(); ++i) s += (i ? " " : "") + parts[i];
    if (!f.label.empty()) s += (s.empty() ? "" : "  ") + ("\"" + clean_label(f.label) + "\"");
    // Terse per-finding diagnostic tags, e.g. "[warn: no-oob]". The short tag is
    // the code with a redundant leading "<type>-" stripped; the full message is
    // in the diagnostics section.
    for (const auto& d : f.diagnostics) {
        std::string tag = d.code;
        std::string pfx = f.type + "-";
        if (tag.rfind(pfx, 0) == 0) tag = tag.substr(pfx.size());
        std::string sev = d.severity == "error" ? "err" : d.severity == "warning" ? "warn" : "info";
        s += (s.empty() ? "" : " ");
        s += p.sev(d.severity) + ("[" + sev + ": " + tag + "]") + p.reset();
    }
    return s;
}

// Left-pad-to-width then wrap in optional color; width counts the plain text.
void col(std::string& line, const std::string& text, size_t width, const char* color,
         const char* reset) {
    line += color;
    line += text;
    line += reset;
    if (text.size() < width) line.append(width - text.size(), ' ');
}

}  // namespace

// A swarm of same-type siblings (a cert bundle, a pile of icons) collapses to
// one row + a count, unless -A. High-value or structural kinds never collapse.
constexpr size_t SWARM = 4;
bool keep_expanded(const Finding& f) {
    if (f.type == "private_key") return true;
    return f.category == "container" || f.category == "filesystem" ||
           f.category == "bootloader" || f.category == "executable";
}

// Render the findings as a containment tree: a finding whose byte range sits
// inside a container (filesystem/container category) is drawn indented beneath
// it with tree connectors, recursively. Collapses per-parent swarms. Columns
// (SIZE/TYPE/TIER/NOTES) stay aligned; the tree glyphs live in the OFFSET column.
void emit_findings_tree(std::string& o, const Palette& p, const std::vector<Finding>& fs,
                        bool all) {
    const size_t n = fs.size();
    auto is_container = [](const Finding& f) {
        return f.category == "filesystem" || f.category == "container";
    };
    // parent[i] = tightest container that strictly encloses finding i.
    std::vector<int> parent(n, -1);
    for (size_t i = 0; i < n; ++i) {
        size_t best = SIZE_MAX;
        for (size_t j = 0; j < n; ++j) {
            if (j == i || !is_container(fs[j])) continue;
            size_t aS = fs[j].offset, aE = aS + fs[j].size;
            size_t bS = fs[i].offset, bE = bS + fs[i].size;
            if (aS <= bS && bE <= aE && fs[j].size > fs[i].size && fs[j].size < best) {
                best = fs[j].size;
                parent[i] = static_cast<int>(j);
            }
        }
    }
    std::vector<std::vector<int>> kids(n);
    std::vector<int> roots;
    for (size_t i = 0; i < n; ++i)
        (parent[i] < 0 ? roots : kids[parent[i]]).push_back(static_cast<int>(i));

    // One rendered line: a finding row, a member (volume) row, or a swarm note.
    struct Row {
        std::string first;    // tree prefix + offset/name (or prefix for a note)
        const Finding* f = nullptr;
        const Member* mem = nullptr;
        std::string note;     // summary text
    };
    std::vector<Row> rows;

    struct Item {
        int idx = -1;                 // finding child index, or -1
        const Member* mem = nullptr;  // member (volume) child
        std::string sum_type;         // swarm summary
        size_t sum_more = 0, sum_bytes = 0;
    };

    // Render a flat list of leaf findings (a volume's embedded keys/certs) under
    // `prefix`, with the same per-parent swarm collapse (keys kept, certs folded).
    auto leaf = [&](const std::vector<const Finding*>& cs, const std::string& prefix) {
        std::map<std::string, size_t> cnt, bytes;
        for (auto* c : cs) { cnt[c->type]++; bytes[c->type] += c->size; }
        struct LI { const Finding* f; std::string st; size_t more, by; };
        std::vector<LI> items;
        std::set<std::string> em;
        for (auto* c : cs) {
            bool coll = !all && !keep_expanded(*c) && cnt[c->type] > SWARM;
            if (coll) {
                if (em.count(c->type)) continue;
                em.insert(c->type);
                items.push_back({c, "", 0, 0});
                items.push_back({nullptr, c->type, cnt[c->type] - 1, bytes[c->type]});
            } else {
                items.push_back({c, "", 0, 0});
            }
        }
        for (size_t i = 0; i < items.size(); ++i) {
            std::string conn = (i + 1 == items.size()) ? "└─ " : "├─ ";
            if (!items[i].f) {
                rows.push_back({prefix + conn, nullptr, nullptr,
                                "… +" + std::to_string(items[i].more) + " more " + items[i].st +
                                    " (" + human_size(items[i].by) + ", -A to list)"});
                continue;
            }
            rows.push_back({prefix + conn + hex_off(items[i].f->offset), items[i].f, nullptr, ""});
        }
    };

    // Render the children of `pidx` (its members first, then contained findings
    // with per-parent swarm collapse). pidx = -1 for the top-level roots.
    std::function<void(int, const std::vector<int>&, const std::string&, bool)> render =
        [&](int pidx, const std::vector<int>& ch, const std::string& prefix, bool top) {
            std::vector<Item> items;
            if (pidx >= 0)
                for (const auto& m : fs[pidx].members) { Item it; it.mem = &m; items.push_back(it); }
            std::map<std::string, size_t> cnt, bytes;
            for (int c : ch) { cnt[fs[c].type]++; bytes[fs[c].type] += fs[c].size; }
            std::set<std::string> emitted;
            for (int c : ch) {
                const Finding& f = fs[c];
                bool coll = !all && !keep_expanded(f) && cnt[f.type] > SWARM;
                if (coll) {
                    if (emitted.count(f.type)) continue;
                    emitted.insert(f.type);
                    Item a; a.idx = c; items.push_back(a);
                    Item s; s.sum_type = f.type; s.sum_more = cnt[f.type] - 1;
                    s.sum_bytes = bytes[f.type]; items.push_back(s);
                } else {
                    Item a; a.idx = c; items.push_back(a);
                }
            }
            for (size_t i = 0; i < items.size(); ++i) {
                bool last = (i + 1 == items.size());
                std::string conn = top ? "" : (last ? "└─ " : "├─ ");
                const Item& it = items[i];
                if (it.mem) {
                    Row r; r.first = prefix + conn + it.mem->name; r.mem = it.mem;
                    rows.push_back(r);
                    if (!it.mem->children.empty()) {
                        std::vector<const Finding*> cs;
                        for (const auto& c : it.mem->children) cs.push_back(&c);
                        leaf(cs, prefix + (top ? "" : (last ? "   " : "│  ")));
                    }
                    continue;
                }
                if (it.idx < 0) {  // swarm summary
                    rows.push_back({prefix + conn, nullptr, nullptr,
                                    "… +" + std::to_string(it.sum_more) + " more " + it.sum_type +
                                        " (" + human_size(it.sum_bytes) + ", -A to list)"});
                    continue;
                }
                int idx = it.idx;
                rows.push_back({prefix + conn + hex_off(fs[idx].offset), &fs[idx], nullptr, ""});
                if (!fs[idx].members.empty() || !kids[idx].empty())
                    render(idx, kids[idx], prefix + (top ? "" : (last ? "   " : "│  ")), false);
            }
        };
    render(-1, roots, "", true);

    // Column widths (first column counts the tree glyphs; they are ASCII-width
    // box chars, 3 bytes/1 col in UTF-8, so measure display width, not bytes).
    auto disp_w = [](const std::string& s) {
        size_t w = 0;
        for (size_t i = 0; i < s.size();) {
            unsigned char c = s[i];
            i += (c < 0x80) ? 1 : (c < 0xE0 ? 2 : (c < 0xF0 ? 3 : 4));
            ++w;
        }
        return w;
    };
    size_t w_off = 6, w_size = 4, w_type = 4, w_tier = 4;
    for (const auto& r : rows) {
        if (r.f) {
            w_off = std::max(w_off, disp_w(r.first));
            w_size = std::max(w_size, human_size(r.f->size).size());
            w_type = std::max(w_type, r.f->type.size());
            w_tier = std::max(w_tier, r.f->confidence_tier.size());
        } else if (r.mem) {
            w_off = std::max(w_off, disp_w(r.first));
            w_size = std::max(w_size, human_size(r.mem->size).size());
            w_type = std::max(w_type, r.mem->note.size());
        }
    }
    o += p.dim();
    std::string h;
    col(h, "OFFSET", w_off, "", "");
    h += "  ";
    col(h, "SIZE", w_size, "", "");
    h += "  ";
    col(h, "TYPE", w_type, "", "");
    h += "  ";
    col(h, "TIER", w_tier, "", "");
    h += "  NOTES";
    o += h + p.reset() + "\n";

    for (const auto& r : rows) {
        size_t pad = w_off > disp_w(r.first) ? w_off - disp_w(r.first) : 0;
        if (!r.f && !r.mem) {  // summary note, indented under its parent
            o += p.dim() + r.first + r.note + p.reset() + "\n";
            continue;
        }
        if (r.mem) {  // volume row: name (bold) in the OFFSET col, size, content-type
            std::string name = r.mem->name;
            std::string pre = r.first.substr(0, r.first.size() - name.size());
            std::string line = p.dim() + pre + p.reset() + p.bold() + name + p.reset();
            line.append(pad, ' ');
            line += "  ";
            col(line, human_size(r.mem->size), w_size, "", "");
            line += "  ";
            col(line, r.mem->note, w_type, p.dim(), p.reset());
            while (!line.empty() && line.back() == ' ') line.pop_back();
            o += line + "\n";
            continue;
        }
        // Finding row: dim tree glyphs, magenta offset. Split the trailing hex.
        std::string offhex = hex_off(r.f->offset);
        std::string pre = r.first.substr(0, r.first.size() - offhex.size());
        std::string line = p.dim() + pre + p.reset() + p.off() + offhex + p.reset();
        line.append(pad, ' ');
        line += "  ";
        col(line, human_size(r.f->size), w_size, "", "");
        line += "  ";
        col(line, r.f->type, w_type, p.sec(*r.f), p.reset());
        line += "  ";
        col(line, r.f->confidence_tier, w_tier, p.tier(r.f->confidence_tier), p.reset());
        line += "  ";
        line += p.dim() + notes_for(*r.f, p) + p.reset();
        while (!line.empty() && line.back() == ' ') line.pop_back();
        o += line + "\n";
    }
}

// A flattened diagnostic for rendering: the finding's offset/type + the message.
struct DiagRow {
    std::string severity, code, type, message;
    size_t offset;
};

std::vector<DiagRow> gather_diagnostics(const std::vector<Finding>& fs) {
    std::vector<DiagRow> rows;
    for (const auto& f : fs)
        for (const auto& d : f.diagnostics)
            rows.push_back({d.severity, d.code, f.type, d.message, f.offset});
    // errors first, then warnings, then info; ties by offset.
    auto rank = [](const std::string& s) { return s == "error" ? 0 : s == "warning" ? 1 : 2; };
    std::sort(rows.begin(), rows.end(), [&](const DiagRow& a, const DiagRow& b) {
        if (rank(a.severity) != rank(b.severity)) return rank(a.severity) < rank(b.severity);
        return a.offset < b.offset;
    });
    return rows;
}

// The diagnostics section: a table SEVERITY | OFFSET | TYPE | MESSAGE listing
// every finding's diagnostics. The single place to scan for trouble; the NOTES
// column flags each in situ.
void emit_diagnostics_section(std::string& o, const Palette& p, const std::vector<DiagRow>& rows) {
    if (rows.empty()) return;
    size_t w_sev = 8, w_off = 6, w_type = 4;
    for (const auto& r : rows) {
        w_sev = std::max(w_sev, r.severity.size());
        w_off = std::max(w_off, hex_off(r.offset).size());
        w_type = std::max(w_type, r.type.size());
    }
    o += p.dim();
    o += "\ndiagnostics:\n";
    o += p.reset();
    std::string h = "  ";
    col(h, "SEVERITY", w_sev, "", "");
    h += "  ";
    col(h, "OFFSET", w_off, "", "");
    h += "  ";
    col(h, "TYPE", w_type, "", "");
    h += "  MESSAGE";
    o += p.dim() + h + p.reset() + "\n";
    for (const auto& r : rows) {
        std::string line = "  ";
        col(line, r.severity, w_sev, p.sev(r.severity), p.reset());
        line += "  ";
        col(line, hex_off(r.offset), w_off, p.off(), p.reset());
        line += "  ";
        col(line, r.type, w_type, "", "");
        line += "  ";
        line += r.message;
        o += line + "\n";
    }
}

std::string emit_file_human(const std::vector<Finding>& findings,
                            const std::vector<Region>& regions, const std::string& footer,
                            bool color, bool all) {
    Palette p{color};
    std::string o;

    // Errors-only banner at the very top: a "moria could not do this" result
    // must not be buried under a long findings table. Warnings/info live only in
    // the diagnostics section and the NOTES column.
    auto diags = gather_diagnostics(findings);
    size_t nerr = 0;
    for (const auto& d : diags)
        if (d.severity == "error") ++nerr;
    if (nerr > 0) {
        o += p.sev("error");
        o += (nerr == 1 ? "! 1 error" : "! " + std::to_string(nerr) + " errors");
        o += " — see diagnostics below\n\n";
        o += p.reset();
    }

    if (findings.empty()) {
        o += p.dim();
        o += "No known structures identified.\n";
        o += p.reset();
    } else {
        emit_findings_tree(o, p, findings, all);
    }

    // What's wrong with what's here — after the table, before the regions/footer.
    emit_diagnostics_section(o, p, diags);

    if (!regions.empty()) {
        o += p.dim();
        o += "\nunidentified regions:\n";
        o += p.reset();
        for (const auto& r : regions) {
            char buf[128];
            std::snprintf(buf, sizeof(buf), "  %-10s %-9s  entropy %.2f%s\n", hex_off(r.offset).c_str(),
                          human_size(r.size).c_str(), r.entropy,
                          r.entropy >= 7.2 ? "  (likely encrypted/compressed)" : "");
            o += buf;
        }
    }

    if (!footer.empty()) {
        o += "\n";
        o += p.dim() + footer + p.reset();
    }
    return o;
}

// Split a root-relative path into (directory-with-trailing-slash, basename).
// A path with no slash is a root-level file: directory "./".
static std::pair<std::string, std::string> split_dir(const std::string& path) {
    auto slash = path.rfind('/');
    if (slash == std::string::npos) return {"./", path};
    return {path.substr(0, slash + 1), path.substr(slash + 1)};
}

std::string emit_tree_human(const TreeResult& tr, const std::string& footer, bool color, bool all) {
    Palette p{color};
    std::string o;

    if (!tr.by_type.empty()) {
        o += p.dim();
        o += "by type:  ";
        o += p.reset();
        for (size_t i = 0; i < tr.by_type.size(); ++i) {
            if (i) o += p.dim(), o += " · ", o += p.reset();
            o += tr.by_type[i].first + " " + std::to_string(tr.by_type[i].second);
        }
        o += "\n";
    }

    if (!tr.notable.empty()) {
        constexpr size_t kMaxNotable = 40;  // keep the view scannable; JSON has all
        size_t shown = all ? tr.notable.size() : std::min(tr.notable.size(), kMaxNotable);

        // Width of the basename column, over the rows we will actually print.
        size_t w_base = 4, w_type = 4;
        for (size_t i = 0; i < shown; ++i) {
            w_base = std::max(w_base, split_dir(tr.notable[i].path).second.size());
            w_type = std::max(w_type, tr.notable[i].finding.type.size());
        }
        w_base = std::min<size_t>(w_base, 52);

        o += p.dim();
        o += "\nnotable (" + std::to_string(tr.notable.size()) + "):\n";
        o += p.reset();

        // Notable is path-sorted, so entries in the same directory are already
        // consecutive: print each directory once as a heading, its files under it.
        std::string cur_dir;
        for (size_t i = 0; i < shown; ++i) {
            const auto& n = tr.notable[i];
            auto [dir, base] = split_dir(n.path);
            if (dir != cur_dir) {
                cur_dir = dir;
                o += "  " + std::string(p.dim()) + dir + p.reset() + "\n";
            }
            if (base.size() > 52) base = "…" + base.substr(base.size() - 51);
            std::string row = "    ";
            col(row, base, w_base, "", "");
            row += "  ";
            // Red = security-sensitive (a private key to act on); otherwise the
            // confidence tier. Matches the single-file findings tree.
            const char* tc = p.sec(n.finding);
            if (!*tc) tc = p.tier(n.finding.confidence_tier);
            col(row, n.finding.type, w_type, tc, p.reset());
            row += "  ";
            row += p.dim();
            row += notes_for(n.finding, p);
            row += p.reset();
            while (!row.empty() && row.back() == ' ') row.pop_back();
            o += row + "\n";
        }
        if (tr.notable.size() > shown) {
            o += p.dim();
            o += "  … and " + std::to_string(tr.notable.size() - shown) +
                 " more (-A for all, or use JSON)\n";
            o += p.reset();
        }
    }

    if (!footer.empty()) {
        if (!o.empty()) o += "\n";  // blank separator only when there's content above
        o += p.dim() + footer + p.reset();
    }
    return o;
}

}  // namespace ft

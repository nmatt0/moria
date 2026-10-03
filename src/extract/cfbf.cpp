// cfbf.cpp — compound file (CFBF) extractor. See the header.
#include "extract/cfbf.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "cfbf_parse.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

// Compound-file names are arbitrary UTF-16; MSI table names decode to things
// like "_StringPool", and the summary stream starts with a control character.
// Keep them recognizable but never path-active.
std::string safe_name(const std::string& name) {
    std::string out;
    for (char ch : name) {
        const unsigned char u = static_cast<unsigned char>(ch);
        if (u < 0x20 || ch == '/' || ch == '\\' || ch == ':' || ch == '*' || ch == '?' ||
            ch == '"' || ch == '<' || ch == '>' || ch == '|')
            out += '_';
        else
            out += ch;
    }
    while (!out.empty() && (out.back() == '.' || out.back() == ' ')) out.pop_back();
    if (out.empty() || out == "." || out == "..") out = "_unnamed";
    return out;
}

// Walk the directory tree, recording each stream's path. Siblings form a
// red-black tree inside their storage; a storage's `child` heads the tree of
// what it holds. `seen` breaks the cycles a corrupt directory can describe.
//
// The walk is iterative with an explicit work stack, not recursive: the entry
// count is bounded only by kMaxDirEntries (262144), and a crafted directory can
// lay those out as one long linear left/right sibling chain (or a deep storage
// nesting). Recursing per node would overflow the call stack on such input; the
// explicit stack lives on the heap and cannot.
void walk_tree(const Cfbf& c, uint32_t root_idx, std::vector<std::string>& paths,
               std::vector<char>& seen) {
    struct Node {
        uint32_t idx;
        const std::string* prefix;
    };
    const std::string empty;
    // A storage's path is the prefix its children carry, so it must outlive the
    // child nodes still on the stack. These are heap-allocated and only ever
    // appended, so a pointer into the pool stays valid as it grows.
    std::vector<std::unique_ptr<std::string>> pool;
    std::vector<Node> stack;
    stack.push_back({root_idx, &empty});

    while (!stack.empty()) {
        const Node n = stack.back();
        stack.pop_back();
        const uint32_t idx = n.idx;
        if (idx == kCfbfNoStream || idx >= c.entries.size() || seen[idx]) continue;
        seen[idx] = 1;
        const CfbfEntry& e = c.entries[idx];
        const std::string& prefix = *n.prefix;

        const std::string name = safe_name(e.name);
        std::string full = prefix.empty() ? name : prefix + "/" + name;
        if (e.type == kCfbfStream) paths[idx] = full;

        // Siblings inherit this node's prefix; a storage's children get `full`.
        stack.push_back({e.left, n.prefix});
        stack.push_back({e.right, n.prefix});
        if (e.type == kCfbfStorage) {
            pool.push_back(std::make_unique<std::string>(std::move(full)));
            stack.push_back({e.child, pool.back().get()});
        }
    }
}

}  // namespace

bool extract_cfbf(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out) {
    out.offset = f.offset;
    out.type = "cfbf";
    out.root = subdir;

    Cfbf c;
    if (!cfbf_parse(r, f.offset, c)) {
        out.status = "error:header";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    out.consumed = c.span;

    // Resolve every stream's path through the storage tree. An entry the tree
    // does not reach still gets written (flat, under its own name) rather than
    // dropped: a damaged directory should cost you the hierarchy, not the data.
    std::vector<std::string> paths(c.entries.size());
    std::vector<char> seen(c.entries.size(), 0);
    walk_tree(c, c.entries[0].child, paths, seen);

    std::unordered_map<std::string, int> used;
    for (size_t i = 0; i < c.entries.size(); ++i) {
        const CfbfEntry& e = c.entries[i];
        if (e.type != kCfbfStream || e.size == 0) continue;

        std::vector<uint8_t> data;
        if (!cfbf_stream(r, f.offset, c, e, data)) {
            out.warnings.push_back(safe_name(e.name) + ": broken sector chain");
            continue;
        }

        std::string rel = paths[i].empty() ? safe_name(e.name) : paths[i];
        const int n = used[rel]++;
        if (n) rel += "." + std::to_string(n);  // same name in two storages

        if (!root.write_file(subdir + "/" + rel, data, 0644)) {
            out.status = "error:write";
            return true;
        }
        out.files++;
        out.bytes += data.size();
    }

    if (out.files == 0) {
        if (out.status.empty()) out.status = "error:empty";
    } else if (!out.warnings.empty()) {
        out.status = "partial";
    } else {
        out.status = "ok";
    }
    return true;
}

}  // namespace ft

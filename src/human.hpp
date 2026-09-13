// human.hpp — human-readable ("pretty") rendering of scan results.
//
// JSON (json.hpp) stays the default, machine-facing output. These renderers
// produce a compact, aligned, optionally-colored text view for a person reading
// a terminal: a header line, the one-line assessment, a findings table, and (for
// a single file) the unidentified regions. Selected with `--human` / `-H`.
#pragma once

#include <string>
#include <vector>

#include "assess.hpp"
#include "finding.hpp"
#include "tree.hpp"

namespace ft {

// Single file: the findings table (a containment tree) + unidentified regions,
// then a plain `footer` (run stats, extraction/hidden notes) after a blank line.
// When `all` is false, a swarm of same-type siblings (compressed nodes, a cert
// bundle) collapses to one row + a count; `all` lists every finding.
// `verbose` (the -v flag) shows full labels instead of ellipsis-truncating them.
std::string emit_file_human(const std::vector<Finding>& findings,
                            const std::vector<Region>& regions, const std::string& footer,
                            bool color, bool all, bool verbose = false);

// Directory tree: by-type counts + notable table (grouped by directory), then a
// plain `footer` (run stats) after a blank line. Mirrors the single-file view:
// no header, no inline assessment (that stays in JSON). `all` lifts the
// notable-row cap.
std::string emit_tree_human(const TreeResult& tr, const std::string& footer, bool color,
                            bool all, bool verbose = false);

}  // namespace ft

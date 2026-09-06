// json.hpp — hand-rolled JSON emit (zero deps for v0, per phase2-design §12).
#pragma once

#include <string>
#include <vector>

#include "assess.hpp"
#include "finding.hpp"
#include "tree.hpp"

namespace ft {

// Serialize the result of scanning one file (phase2-design §5.1) with the A2/A3
// additions: a decision-useful `assessment` line and `unidentified_regions`.
std::string emit_file_json(const std::string& path, size_t file_size,
                           const std::vector<Finding>& findings,
                           const std::vector<Region>& regions, const std::string& assessment,
                           const std::string& extraction = "");

// Streaming directory/tree scan JSON (phase2-design §5.2). Emitted in three parts
// so the scan never buffers every file (G7): `_head` opens the object and the
// `files` array, `emit_tree_file` appends one file object per scanned file (pass
// its running index for comma separation), and `_tail` closes the array and
// appends `file_count`, `assessment`, `by_type`, and `notable`.
std::string emit_tree_json_head(const std::string& root);
std::string emit_tree_file(const FileResult& fr, size_t index);
std::string emit_tree_json_tail(const TreeResult& tr, const std::string& assessment);

}  // namespace ft

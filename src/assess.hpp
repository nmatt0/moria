// assess.hpp — A2 (unidentified regions + entropy) and A3 (assessment line).
// Turns a raw finding list into decision-useful signal for an LLM/analyst:
// where the *unidentified* bytes are and how random they look (encrypted?), and
// a one-line human read of the whole file/tree.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "finding.hpp"
#include "reader.hpp"
#include "tree.hpp"

namespace ft {

struct Region {
    size_t offset;
    size_t size;
    double entropy;  // bits/byte, 0-8
};

// Whole-file entropy (sampled for large files to stay cheap).
double whole_file_entropy(const Reader& r);

// Shannon entropy (bits/byte, 0-8) over [off, off+len), sampling large ranges so
// it stays cheap on a multi-GB finding. Used by the -E per-finding entropy column.
double region_entropy(const Reader& r, size_t off, size_t len);

// Byte ranges not covered by any structural finding, each with its
// entropy. Only regions >= min_size are returned. Useful to flag encrypted or
// compressed blobs the identifier didn't recognize.
std::vector<Region> unidentified_regions(const Reader& r, const std::vector<Finding>& findings,
                                         size_t min_size);

// One-line, decision-useful read of a single file. When `entropy_on` is false
// (entropy analysis not requested, i.e. no -E), all entropy-derived language is
// omitted: no whole-file-entropy readout and no "possible encryption" note.
std::string assess_file(const std::vector<Finding>& findings, size_t file_size,
                        const std::vector<Region>& regions, double file_entropy, bool entropy_on);

// One-line read of a whole tree scan.
std::string assess_tree(const TreeResult& tr);

}  // namespace ft

// tree.hpp — directory/tree scan result types (phase2-design §5.2).
#pragma once

#include <functional>
#include <string>
#include <vector>

#include "finding.hpp"
#include "signature.hpp"

namespace ft {

struct FileResult {
    std::string path;          // path relative to the scanned root
    size_t size = 0;
    std::vector<Finding> findings;
    std::string primary_type;  // highest-confidence finding's type, or "unknown"/"unreadable"
    bool ok = true;
    std::string error;
};

struct Notable {
    std::string path;
    Finding finding;
};

// Aggregate result of a tree scan. Per-file results are NOT retained: they are
// streamed to the scan's `sink` as each file completes (in path order), and only
// the bounded aggregates below are kept. So memory stays flat over an arbitrarily
// large tree (see G7). `notable` is the pentest-relevant subset and stays small.
struct TreeResult {
    std::string root;
    size_t file_count = 0;
    size_t bytes = 0;           // total bytes of all scanned files
    size_t finding_count = 0;   // total findings (incl. container member children)
    size_t crypto_count = 0;    // key/cert findings, for the assessment
    std::vector<std::pair<std::string, size_t>> by_type;  // primary_type -> count, sorted desc
    std::vector<Notable> notable;
};

// Whether a finding is worth surfacing in `notable` (pentest-relevant kinds).
bool is_notable(const Finding& f);

// Called once per scanned file, in path order, as the scan progresses. Lets a
// caller stream per-file output (e.g. the JSON `files` array) without the scan
// holding every file's findings in memory. Empty = no per-file callback.
using FileSink = std::function<void(const FileResult&)>;

// Recursively scan `root` with `nthreads` workers. Regular files only (symlinks
// and special files skipped). Deterministic: files are processed in sorted-path
// order and `sink` is invoked in that order regardless of thread completion.
// Memory is bounded to a window of in-flight files plus the aggregates, so a
// huge tree does not accumulate.
TreeResult scan_tree(const std::string& root, const std::vector<Signature>& sigs,
                     unsigned nthreads, bool list, const FileSink& sink = {});

}  // namespace ft

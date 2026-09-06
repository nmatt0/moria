// manifest.hpp — record of what extraction carved, and the extractor registry.
//
// An extractor turns one Finding (already identified + validated) into files
// under a SafeRoot, appending an Extracted row per output. The manifest is
// written as manifest.json in the out dir AND folded into moria's normal JSON
// (an "extracted" array) so an LLM caller sees offsets -> paths in one place.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

struct Extracted {
    size_t offset = 0;         // where in the source image this came from
    std::string type;          // format ("squashfs", ...)
    std::string root;          // top output subdir under the extraction root
    std::string status;        // "ok" | "partial" | "unsupported:<codec>" | "error:<why>"
    size_t files = 0;          // regular files written
    size_t dirs = 0;
    size_t symlinks = 0;
    size_t bytes = 0;          // total uncompressed bytes written
    uint64_t consumed = 0;     // input bytes this finding spanned (0 = unknown)
    size_t depth = 1;          // recursion level (1 = top-level input)
    std::vector<std::string> warnings;
};

struct Manifest {
    std::vector<Extracted> entries;
    std::string source;      // source file path
    bool capped = false;     // a recursion guard (depth/files/bytes/ratio) tripped
    std::string cap_reason;  // which guard, when capped
};

// One extractor: pull `f` out of `r` into `root`, describing results in `out`.
// `subdir` is a unique-per-finding directory name the extractor should create
// under the root (e.g. "0x10000-squashfs"). Returns false only on hard failure;
// unsupported-codec / partial results still return true with status set.
using Extractor = bool (*)(const Reader& r, const Finding& f, SafeRoot& root,
                           const std::string& subdir, Extracted& out);

Extractor find_extractor(const std::string& type);

// Serialize a manifest to JSON (also used for the in-output "extracted" array).
std::string manifest_to_json(const Manifest& m);

}  // namespace ft

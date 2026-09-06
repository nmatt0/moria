// squashfs.hpp — SquashFS v4.0 extractor.
//
// Walks the superblock -> inode table -> directory table -> data/fragment
// blocks and reconstructs the file tree under a SafeRoot. All decompression
// goes through extract/decompress.hpp; all writes through extract/safepath.hpp.
// v4 little-endian only (the format in every modern firmware); legacy v1-3 and
// the big-endian magics are out of scope for now.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_squashfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                      Extracted& out);

}  // namespace ft

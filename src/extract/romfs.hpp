// romfs.hpp — Linux romfs extractor.
//
// romfs is a tiny read-only filesystem: a superblock ("-rom1fs-") then a chain
// of 16-byte-aligned file headers, each with a big-endian next-header pointer
// (low bits = type), a spec field (first child for dirs), a size, and a
// NUL-padded name followed by the file data. This extractor walks the header
// chains from the root directory and writes regular files, directories, and
// symlinks under a SafeRoot. All reads go through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_romfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out);

}  // namespace ft

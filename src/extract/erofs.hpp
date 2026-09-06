// erofs.hpp — EROFS (Enhanced Read-Only File System) extractor.
//
// EROFS is the modern read-only firmware/Android filesystem. Superblock at
// offset 1024 gives the block size, the metadata start block, and the root
// inode id (nid). Inodes are 32-byte "compact" or 64-byte "extended" slots
// addressed by nid; a datalayout field selects how the data is stored:
// FLAT_PLAIN (contiguous blocks), FLAT_INLINE (full blocks + an inline tail
// after the inode/xattrs), or COMPRESSION (per-cluster lz4/lzma/...).
// Directories are blocks of erofs_dirent records with names packed at the tail.
// This extractor walks from the root nid and writes files/dirs/symlinks. All
// reads go through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_erofs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out);

}  // namespace ft

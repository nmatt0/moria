// cramfs.hpp — cramfs (Compressed ROM filesystem) extractor.
//
// cramfs is a tiny read-only filesystem: a 76-byte superblock whose last 12
// bytes are the root inode, then a tree of 12-byte bit-packed inodes each
// followed by its NUL-padded name. Directory data is a run of child inodes;
// file data is an array of zlib-compressed 4 KiB blocks preceded by their end
// offsets. This extractor walks the tree from the root inode and writes regular
// files, directories, and symlinks under a SafeRoot. Little-endian images (the
// common case). All reads go through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_cramfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out);

}  // namespace ft

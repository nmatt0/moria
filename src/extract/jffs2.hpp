// jffs2.hpp — JFFS2 read-only extractor.
//
// JFFS2 is a log-structured flash filesystem: the image is a stream of nodes
// (inode data nodes + directory-entry nodes), and a file's contents are the
// newest data nodes covering each byte range. This extractor scans the nodes,
// reassembles each inode from its highest-version data nodes, rebuilds the tree
// from the dirents, and writes files/dirs/symlinks under a SafeRoot. Node data
// is decompressed with none/zero/rtime (internal) + zlib + lzo (internal LZO1X).
// Both endiannesses are handled. All reads go through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_jffs2(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out);

}  // namespace ft

// hfsplus.hpp — HFS+ / HFSX (read-only) extractor.
//
// HFS+ is the classic macOS filesystem (also seen on some appliance/NAS images).
// A Volume Header at offset 1024 (big-endian) names the special files by fork,
// each an array of up to 8 (startBlock, blockCount) extents. The Catalog File is
// a B-tree keyed by (parentCNID, nodeName); its leaf nodes hold folder and file
// records. This extractor reads the catalog fork, walks the leaf-node chain to
// collect every folder/file record, rebuilds the tree from the root folder
// (CNID 2), and writes regular files, directories, and symlinks under a SafeRoot.
// File data comes from the data fork's inline extents (files needing the extents
// overflow file are recovered up to their inline extents, then marked partial).
// All reads go through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_hfsplus(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                     Extracted& out);

}  // namespace ft

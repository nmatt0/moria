// yaffs2.hpp — YAFFS2 read-only extractor (standard MTD OOB layout).
//
// A YAFFS2 image is a sequence of fixed chunks, each a data page followed by a
// spare/OOB area holding the packed tags (sequence, object id, chunk id, byte
// count). Object-header chunks (chunk id 0) carry a yaffs_ObjectHeader (type,
// parent, name, mode, size, symlink alias); data chunks (chunk id >= 1) carry
// file bytes at (chunkId-1)*pagesize. This extractor detects the page/spare
// geometry, reads the tags at the standard MTD offset, reassembles each object
// newest-wins, and rebuilds the tree from the root object (1). It needs the OOB:
// a data-only dump (spare stripped) has no tags and cannot be reconstructed by
// any tool — moria reports that rather than guessing. All reads go through Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_yaffs2(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out);

}  // namespace ft

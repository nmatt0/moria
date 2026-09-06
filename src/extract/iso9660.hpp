// iso9660.hpp — ISO 9660 (CD/DVD/UDF-bridge) extractor, with Rock Ridge.
//
// ISO 9660 backs optical images and many firmware update / recovery packages.
// The Primary Volume Descriptor at sector 16 (offset 32768) points at the root
// directory record; directory records form a tree of extents. Rock Ridge (SUSP)
// entries after each record carry the real long name (NM), symlink target (SL),
// and posix attributes, so a Linux-authored ISO round-trips faithfully. This
// extractor walks the tree, decodes Rock Ridge, and writes files/dirs/symlinks.
// All reads go through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_iso9660(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                     Extracted& out);

}  // namespace ft

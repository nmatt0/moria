// zip.hpp — ZIP archive extractor.
//
// ZIP is the container behind APKs, jars, OTA update.zip, and many firmware
// bundles. The End Of Central Directory record (PK\5\6) points at the central
// directory (PK\1\2 headers), which lists every member with its name, sizes,
// compression method, and local-header offset. This extractor walks the central
// directory and writes each member: stored (copied) or deflate (via the codec
// seam), with unix permissions and symlinks from the external attributes. All
// reads go through the bounds-checked Reader; writes through SafeRoot.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_zip(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

}  // namespace ft

// cpio.hpp — cpio (newc/crc ASCII) archive extractor.
//
// Walks the 070701/070702 entry chain from the finding's offset and writes each
// member (regular file, directory, symlink) under a SafeRoot. Uncompressed, so
// no decompressor is involved; reads go through the bounds-checked Reader and
// writes through SafeRoot (openat + O_NOFOLLOW). The odc (070707) octal variant
// is not extracted here (identification only). Hostile headers yield partial
// output, never OOB reads or writes outside the root.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_cpio(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out);

}  // namespace ft

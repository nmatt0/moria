// ntfs.hpp — NTFS read-only extractor.
//
// NTFS backs Windows recovery partitions and some appliances. Everything is a
// file described by a 1KB MFT (Master File Table) record holding typed
// attributes: $FILE_NAME (name + parent MFT reference) and $DATA (content,
// resident in the record or non-resident as a runlist of cluster extents). This
// extractor reads the whole MFT (via record 0's own $DATA runlist), enumerates
// every in-use record, and rebuilds paths from the parent references — no
// directory-index B-tree walk needed. Writes files and directories; system
// metadata files and reparse points (symlinks) are skipped. All raw reads go
// through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_ntfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out);

}  // namespace ft

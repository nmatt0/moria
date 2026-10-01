// cfbf.hpp — Compound File Binary Format (MSI, .doc, .msg) extractor.
//
// Writes each stream out under the storage path that holds it, so a Windows
// Installer package yields its tables plus the payload cabinet as real files.
// MSI-encoded stream names are decoded, which is what turns an unreadable CJK
// name back into "Data1.cab".
//
// The point of extracting at all is that a compound-file stream is not
// contiguous. Recursion then re-scans what lands here, so the cabinet inside an
// installer is read from its reassembled bytes rather than from a linear walk
// off the end of its first sector run.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_cfbf(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out);

}  // namespace ft

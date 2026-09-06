// tar.hpp — POSIX tar (ustar) extractor.
//
// Walks the 512-byte header records from the finding offset and writes each
// member (regular file, directory, symlink) under a SafeRoot. Handles the ustar
// `prefix` field and GNU long-name ('L') records; pax extended headers are
// skipped (the base header's truncated name is still used). Uncompressed — a
// .tar.gz must be decompressed first. Header checksums gate real records, so
// trailing garbage / the zero-block terminator ends the walk. All reads go
// through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_tar(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

}  // namespace ft

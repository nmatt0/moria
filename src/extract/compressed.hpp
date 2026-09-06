// compressed.hpp — standalone compressed-stream extractor.
//
// Firmware is often a compression wrapper around a filesystem
// (`<header?><gzip|xz|zstd|lz4-frame><squashfs>`). This extractor decompresses
// such a stream to a single file (`decompressed`) so the inner image becomes
// visible to a follow-up moria run. It handles the gzip/xz/zstd/lz4 finding
// types via the streaming path in the decompress seam. All reads go through the
// bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_compressed(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                        Extracted& out);

}  // namespace ft

// android_sparse.hpp — Android sparse-image "unsparse" + inner-FS extractor.
//
// An Android sparse image is a container: a 28-byte header then chunks (RAW /
// FILL / DONT_CARE / CRC) that expand into a raw filesystem image (usually
// ext4). This extractor reconstructs the raw image as a SPARSE output file
// (holes for DONT_CARE, so a mostly-empty multi-GB userdata costs almost no
// disk), then, if the inner image is a filesystem moria can unpack (ext), runs
// that extractor on it. The raw image is left as unsparsed.img either way. All
// reads of the sparse source go through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_android_sparse(const Reader& r, const Finding& f, SafeRoot& root,
                            const std::string& subdir, Extracted& out);

}  // namespace ft

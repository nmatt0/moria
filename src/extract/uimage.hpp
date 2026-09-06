// uimage.hpp — U-Boot legacy uImage payload extractor.
//
// A legacy uImage is a 64-byte big-endian header (magic 0x27051956) followed by
// a payload — usually a compressed kernel or ramdisk. The header records the
// payload size and its compression (none/gzip/lzma/lzo/lz4/...). This extractor
// slices out the payload and decompresses it (via the codec seam) to a single
// file, so the kernel/ramdisk is directly available. All reads go through the
// bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_uimage(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out);

}  // namespace ft

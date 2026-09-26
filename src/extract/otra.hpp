// otra.hpp — Artosyn OTRA firmware image extractor.
//
// Segmented images (VR04): each partition is the concatenation of its LZO1X
// segments; the extractor decompresses them into one raw partition image per
// partition (e.g. "05_userapp0.bin"), which moria then recurses into (UBI ->
// squashfs, uImage, dtb, ...). Flat images (arlink VT4): the body has no tables,
// so the whole flash image is written out as "flash.bin" for downstream carving.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_otra(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out);

}  // namespace ft

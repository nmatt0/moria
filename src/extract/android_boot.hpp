// android_boot.hpp — Android boot image splitter.
//
// An Android boot.img ("ANDROID!" magic) is a page-aligned container of a
// kernel, a ramdisk (usually a gzip/lz4 cpio), and — depending on the header
// version — a second stage, a recovery dtbo, and a dtb. This extractor reads the
// header (versions 0-4), slices out each present component, and writes it as a
// file (kernel, ramdisk, second, recovery_dtbo, dtb) so the ramdisk/dtb can be
// handed back to moria. All reads go through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_android_boot(const Reader& r, const Finding& f, SafeRoot& root,
                          const std::string& subdir, Extracted& out);

}  // namespace ft

// fat.hpp — FAT12/16/32 (+VFAT long names) filesystem extractor.
//
// FAT is ubiquitous on boot/EFI system partitions, SD cards, and many small
// devices. The BIOS parameter block in the boot sector describes the layout: a
// reserved area, one or more File Allocation Tables (cluster chains), a root
// directory (a fixed area on FAT12/16, a cluster chain on FAT32), and the data
// area. Directory entries are 32 bytes; VFAT stores long names in preceding
// 0x0F entries as UTF-16. This extractor follows the chains, decodes long names,
// and writes files/directories. All reads go through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_fat(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

}  // namespace ft

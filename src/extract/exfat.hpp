// exfat.hpp — exFAT filesystem extractor.
//
// exFAT is the filesystem on larger SD cards and removable media. The boot
// sector gives the cluster-heap layout; directories are sequences of 32-byte
// typed entries — a File entry (0x85) followed by a Stream Extension (0xC0, with
// the first cluster, data length, and a "no FAT chain" contiguity flag) and File
// Name entries (0xC1, UTF-16). Data is either contiguous or follows the 32-bit
// FAT. This extractor walks from the root cluster and writes files/directories
// (exFAT has no unix modes or symlinks). All reads go through the Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_exfat(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out);

}  // namespace ft

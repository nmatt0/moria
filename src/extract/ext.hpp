// ext.hpp — ext2/ext3/ext4 read-only extractor.
//
// Walks the superblock -> group descriptors -> inode table -> root directory
// (inode 2) and rebuilds the tree under a SafeRoot: regular files, directories,
// and symlinks. Block mapping handles both ext4 extent trees and the classic
// ext2/3 indirect-block scheme. No journal replay, no write support, no sudo
// (unlike debugfs/mount). All reads go through the bounds-checked Reader; a dump
// truncated below its recorded device size yields a partial result, not a crash.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_ext(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

}  // namespace ft

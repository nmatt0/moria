// f2fs.hpp — F2FS (Flash-Friendly File System) read-only extractor.
//
// F2FS is a log-structured filesystem common on Android userdata/data and some
// embedded flash devices. The superblock (offset
// 1024, magic 0xF2F52010) gives the on-disk layout: the checkpoint, NAT (node
// address table), and main areas. Node ids (nids) are mapped to physical node
// blocks through the NAT (the current copy is selected by a bitmap in the
// checkpoint, with recent updates overlaid from the checkpoint's NAT journal).
// The root inode (nid 3) is walked recursively: directory entries live in
// dentry blocks (or inline in the inode), file data in the inode's direct
// pointers plus direct/indirect/double-indirect node trees, or inline for tiny
// files. This extractor writes files/dirs/symlinks; all reads go through the
// bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_f2fs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out);

}  // namespace ft

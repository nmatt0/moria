// xfs.hpp — XFS (read-only) extractor.
//
// XFS is the SGI/Linux extent-based filesystem (RHEL default, some NAS/appliance
// images). All on-disk fields are big-endian. The superblock (@0) describes the
// geometry: block size, allocation-group size, inode size, and the root inode. An
// inode number encodes (AG, block-in-AG, offset-in-block); each inode's data fork
// is local (inline), extents (a packed bmbt_rec array), or a bmbt B-tree. This
// extractor walks from the root inode: shortform (inline) and block/leaf data-block
// directories, file data from the fork's extents (or bmbt btree), and symlinks
// (inline or extent). Both v4 (96-byte core) and v5 (176-byte core, CRC) inodes.
// All reads go through the bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_xfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

}  // namespace ft

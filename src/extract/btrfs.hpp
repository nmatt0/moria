// btrfs.hpp — btrfs (read-only) extractor.
//
// btrfs addresses everything by logical address; a chunk tree maps logical to
// physical. The superblock (@64 KiB) bootstraps a few chunk mappings (its
// sys_chunk_array) which are enough to read the chunk tree and build the full
// map, then the root tree points at the FS tree (the default subvolume). This
// extractor walks the FS tree's B-tree: INODE_ITEM (mode/size), DIR_INDEX
// (parent -> name -> child), and EXTENT_DATA (file content, inline or a regular
// extent, none/zlib/zstd/lzo compression), and rebuilds files, directories, and
// symlinks under a SafeRoot. Single-device images (the common case); multi-device
// / RAID stripes beyond the first are not followed. All reads go through the
// bounds-checked Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_btrfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out);

}  // namespace ft

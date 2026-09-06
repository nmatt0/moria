// ubifs.hpp — UBI + UBIFS read-only extractor.
//
// UBIFS rides on UBI: the flash is a series of physical erase blocks (PEBs),
// each with UBI EC + VID headers that map it to a (volume, logical-block)
// pair. This extractor first reconstructs each volume's logical block sequence
// from the UBI headers (newest sqnum wins), then parses UBIFS by scanning its
// leaf nodes directly (inode / dentry / data nodes, CRC-gated) rather than
// walking the on-media B-tree, reassembles files from the newest data nodes,
// and rebuilds the tree from the dentries. A raw UBIFS volume (no UBI layer) is
// parsed directly. Node data is decompressed with none/lzo(internal)/zlib(raw
// deflate)/zstd. All reads are range-checked through Reader.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_ubifs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                   Extracted& out);

}  // namespace ft

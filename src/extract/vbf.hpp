// vbf.hpp — VBF (Versatile Binary Format) block extractor.
//
// Walks the VBF block chain that follows the ASCII header and writes one file
// per block, named for its load address (block0_0x00FD0000.bin). Uncompressed
// blocks are copied verbatim; LZSS blocks (data_format_identifier upper nibble
// != 0) are decoded via lzss_vbf_decompress(). Each decoded block's CRC16 is
// verified against the stored value; the extracted images are re-identified when
// moria recurses into them.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_vbf(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

}  // namespace ft

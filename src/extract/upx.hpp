// upx.hpp — reconstruct the original executable from a UPX-packed ELF.
//
// UPX detection (identify) lives in validators/upx.cpp; this is the extractor.
// It reverses UPX's ELF packing to recover the original file byte-for-byte, the
// same output `upx -d` produces:
//   * parse l_info / p_info (original size, block size),
//   * decompress the first block to recover the original Ehdr + Phdrs,
//   * decompress each PT_LOAD segment to its original file offset (unpackExtent),
//   * decompress the inter-segment gaps and the trailing non-loadable region
//     (section headers, .comment, symbol tables) to their offsets.
// Blocks use NRV2B/2D/2E (see ucl.hpp) or LZMA; filtered code blocks are run
// through the matching un-filter (see upx_filter.hpp).
//
// All input is attacker-controlled: every read is bounds-checked through Reader,
// the reconstructed size is capped, and any parse failure yields a partial /
// error status rather than an out-of-bounds access. Only ELF is handled (the
// firmware-relevant case); PE/Mach-O return unsupported.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

struct UpxUnpack {
    std::optional<std::vector<uint8_t>> data;  // reconstructed original file
    std::string status;                        // "ok" | "partial" | "unsupported:.." | "error:.."
    std::string note;                          // human detail for partial/unsupported/error
};

// Reconstruct the original file from the UPX-packed ELF whose stub begins at
// `base` in `r`. On full byte-exact reconstruction, status is "ok" and data is
// set; on a recoverable shortfall (an unimplemented method/filter/layout) status
// is "partial"/"unsupported" with whatever was reconstructed, and data may still
// be set. Never throws.
UpxUnpack upx_unpack(const Reader& r, size_t base);

// Extractor entry point (registered for type "upx" in manifest.cpp). The upx
// finding sits at the PackHeader trailer; this locates the containing ELF stub
// and drives upx_unpack, writing the recovered file under `root`.
bool extract_upx(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

}  // namespace ft

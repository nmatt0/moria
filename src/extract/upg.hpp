// upg.hpp — ".upg" firmware container extractor.
//
// Splits the container into its three structural pieces: header.bin (fixed,
// header_length bytes), payload.bin (payload_size bytes — a 16-byte opaque
// prefix, a constant 8-byte tag, then a short plaintext label, then a large
// region of unconfirmed/likely-encrypted structure), and trailer.bin (16
// bytes, unidentified). No decryption is attempted; this only separates the
// container framing from its payload for further, format-specific analysis.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_upg(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

}  // namespace ft

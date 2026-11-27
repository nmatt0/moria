// sonicare_upg.hpp — Philips Sonicare ".upg" firmware container extractor.
//
// Splits the container into its three structural pieces: header.bin (fixed,
// header_length bytes), payload.bin (payload_size bytes, encrypted past its
// 236-byte plaintext header, key on the MCU), and trailer.bin (16 bytes,
// unidentified). Adds a sonicare_upg-info.txt sidecar serializing that
// plaintext header. No decryption is attempted.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_sonicare_upg(const Reader& r, const Finding& f, SafeRoot& root,
                          const std::string& subdir, Extracted& out);

}  // namespace ft

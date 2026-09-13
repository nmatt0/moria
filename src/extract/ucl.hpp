// ucl.hpp — UCL/NRV decompressors for UPX-packed executables.
//
// UPX compresses each program block with one of the NRV2B / NRV2D / NRV2E
// algorithms from Markus Oberhumer's UCL library, in one of three bit-stream
// widths (byte-wise "_8", little-endian 16-bit "_le16", little-endian 32-bit
// "_le32"). The width and algorithm are encoded together in the b_info block's
// `method` byte:
//
//   2 NRV2B_LE32   3 NRV2B_8   4 NRV2B_LE16
//   5 NRV2D_LE32   6 NRV2D_8   7 NRV2D_LE16
//   8 NRV2E_LE32   9 NRV2E_8  10 NRV2E_LE16
//
// The grammar is per-algorithm (NRV2B uses a single interleaved gamma code for
// the match offset; NRV2D/NRV2E use a double gamma and pack the low bit of the
// offset escape into the match length); the getbit convention is per-width. All
// three widths read bits MSB-first within their word.
//
// This is a clean reimplementation from the published UCL algorithm, validated
// byte-for-byte against `upx -d` output. Input is attacker-controlled, so every
// byte read is bounds-checked and the output is capped at the caller-supplied
// decompressed size; a malformed stream yields std::nullopt, never an
// out-of-bounds access.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ft {

// Is `method` an NRV2B/2D/2E method byte this module can decode (2..10)?
bool ucl_method_supported(uint8_t method);

// Decompress one UCL/NRV block to exactly `out_len` bytes. `method` is the UPX
// b_info method byte (2..10). Returns the decoded bytes, or std::nullopt if the
// method is not an NRV method, the stream is malformed, or exactly out_len bytes
// cannot be produced.
std::optional<std::vector<uint8_t>> ucl_nrv_decompress(uint8_t method,
                                                       std::span<const uint8_t> src,
                                                       size_t out_len);

}  // namespace ft

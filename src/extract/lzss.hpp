// lzss.hpp — LZSS decoder for the VBF (Ford/Volvo) firmware container.
//
// The qvbf LZSS variant used when a VBF block's data_format_identifier upper
// nibble is non-zero (0x10). Parameters: 12-bit-ish window addressed as
// EI=10 index bits, EJ=4 length bits, min match 2, ring size 1024 pre-filled
// with 0x20. A leading 1 bit means "literal byte follows"; a leading 0 bit
// means "back-reference: EI index bits + EJ length bits", and an index of 0 is
// the end-of-stream marker.
//
// Attacker-controlled input: every read goes through a bounds-checked bit
// reader and the output is capped, so a malformed stream yields std::nullopt or
// a truncated buffer, never an out-of-bounds access.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ft {

// Decode a VBF LZSS stream. `max_out` caps the decoded size (anti-DoS). Returns
// the decoded bytes, or std::nullopt if the stream is malformed. Reaching
// max_out stops decoding and returns what was produced.
std::optional<std::vector<uint8_t>> lzss_vbf_decompress(std::span<const uint8_t> src,
                                                        size_t max_out);

}  // namespace ft

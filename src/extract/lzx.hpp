// lzx.hpp — LZX decompression, in the two framings firmware actually ships.
//
// LZX is one bitstream format with two different envelopes around it:
//
//   * Windows CE XIP ROM ("CECompress"/CEDecompressROM): the payload is split
//     into independent 4 KiB blocks, each a self-contained LZX stream prefixed
//     by its own window size and decoded length, indexed by a table of 3-byte
//     end offsets. Used for compressed ROM files and module sections in a .cos
//     / nk.bin image.
//   * MS-CAB (CFFOLDER typeCompress 3): one continuous bitstream for the whole
//     folder, output in 32 KiB frames, with the x86 E8 translation applied per
//     frame rather than per stream.
//
// Both share the block/Huffman/match decoder below. Decoding is linear (matches
// resolve against the bytes already produced) rather than through a circular
// window: the semantics are identical because an LZX match offset never exceeds
// the window size, and it keeps the output a plain buffer.
//
// Every entry point is bounded: output can never exceed the caller's cap, a
// malformed stream yields nullopt rather than a partial lie.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ft {

// Decode a Windows CE ROM CECompress blob (the 3-byte block-offset table plus
// per-block LZX streams) to exactly `out_len` bytes.
//
// A blob's own header declares the decoded length, which for a module .data
// section can be SHORTER than the section's virtual size (the remainder is zero
// at load time). That is a valid encoding, so a short decode is padded with
// zeroes to out_len rather than rejected. Returns nullopt if the block table is
// inconsistent, a block fails to decode, or the stream would exceed out_len.
std::optional<std::vector<uint8_t>> ce_decompress_rom(std::span<const uint8_t> src, size_t out_len);

// Decode one MS-CAB folder's LZX bitstream (all CFDATA payloads concatenated)
// to exactly `out_len` bytes. `window_bits` is 15..21, taken from the high byte
// of CFFOLDER.typeCompress. Returns nullopt on a malformed stream.
std::optional<std::vector<uint8_t>> lzx_decompress_cab(std::span<const uint8_t> src, size_t out_len,
                                                       unsigned window_bits);

}  // namespace ft

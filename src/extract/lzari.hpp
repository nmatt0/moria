// lzari.hpp — LZARI decompressor for RAE Systems / Honeywell RFP sections.
//
// LZARI = LZSS + arithmetic coding. This is the specific variant used by
// Honeywell's NDKTool codec (libndkbinder.so, class LZARIInternal), which is
// NOT stock textbook LZARI: the ring buffer is N=4096 / F=60 / THRESHOLD=2, the
// arithmetic coder renormalizes on 0x8000/0x10000/0x18000 boundaries with a
// 17-bit initial value load, and the position model is a fixed (never-updated)
// cumulative table. Parameters were recovered by disassembling the shipped ARM
// build and confirmed against real compressed/decompressed pairs.
//
// The input is a whole section stream: a 4-byte little-endian decompressed size
// followed by the arithmetic-coded bitstream. Returns the decoded bytes, or
// nullopt if the stream is truncated or the size prefix exceeds `max_out`.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ft {

std::optional<std::vector<uint8_t>> lzari_decompress(std::span<const uint8_t> in, size_t max_out);

}  // namespace ft

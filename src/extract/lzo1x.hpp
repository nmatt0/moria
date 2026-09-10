// lzo1x.hpp — internal, bounds-checked LZO1X decompressor (decompress only).
//
// jffs2 and ubifs store data nodes compressed with the raw LZO1X-1 bitstream
// (the kernel calls lzo1x_decompress_safe on it). liblzo2 uses GPL-2.0, so moria
// uses its own MIT-licensed implementation of the published LZO1X decompression
// method. No code was copied from liblzo2. The record header gives the final
// size, so the caller limits the output and every read and write is checked
// (see CVE-2014-4607 for why these checks matter).
#pragma once

#include <cstddef>
#include <cstdint>

namespace ft {

// Decompress `in_len` bytes at `in` into `out` (capacity `out_cap`). On success
// returns true and sets `out_len` to the number of bytes produced. Returns false
// on any malformed stream, input overrun, or output overrun — never reads or
// writes out of bounds.
//
// When `rle` is true, the LZO-RLE variant (f2fs `lzo-rle`) is decoded: a leading
// `0x11 <version>` stream header enables a zero-run extension in the M4 match
// path. Plain LZO1X callers (jffs2/ubifs/f2fs-lzo/btrfs-lzo) leave `rle` false so
// the format is unchanged.
bool lzo1x_decompress_safe(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap,
                           size_t* out_len, bool rle = false);

}  // namespace ft

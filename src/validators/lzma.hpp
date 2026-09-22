// lzma.hpp — legacy standalone LZMA1 (".lzma alone") identifier.
#pragma once
#include "signature.hpp"
namespace ft {
// The legacy .lzma "alone" container has no magic number: a 13-byte header
// (props byte, 4-byte dict size, 8-byte uncompressed size) then a raw LZMA1
// stream. Anchored on the near-universal firmware header prefix `5D 00 00`
// (props 0x5D = lc3/lp0/pb2, dict a multiple of 64 KiB), this validates the
// header fields and trial-decodes to a clean end-of-stream marker, so a stray
// `5D 00 00` in unrelated data cannot false-positive. Reports `verified`.
bool validate_lzma(ValidatorCtx& ctx);
}  // namespace ft

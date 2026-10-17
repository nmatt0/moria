// lzma.hpp — legacy standalone LZMA1 (".lzma alone") identifier.
#pragma once
#include "signature.hpp"
namespace ft {
// The legacy .lzma "alone" container has no magic number: a 13-byte header
// (props byte, 4-byte dict size, 8-byte uncompressed size) then a raw LZMA1
// stream. Anchored on the props values firmware ships (0x5D = lc3/lp0/pb2, the
// toolchain default; 0x6D = lc1/lp2/pb2, OpenWrt's kernels) followed by a dict
// that is a multiple of 64 KiB, this validates the header fields and
// trial-decodes to a clean end-of-stream marker, so a stray anchor match in
// unrelated data cannot false-positive. Reports `verified`.
bool validate_lzma(ValidatorCtx& ctx);
}  // namespace ft

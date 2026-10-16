// jzlzma.hpp — Ingenic "jzlzma" hardware-LZ77 decoder.
//
// Ingenic T-series SoCs (T10/T20/T23/T30, as in Wansview/Kiwibit IP cameras)
// compress kernel/rootfs images with a proprietary LZ77 variant the vendor
// tools call jzlzma, wrapped by u-boot's mark_rootfs_lzma:
//
//   u32 payload_size        size of the bitstream after this 16-byte header
//   u32 magic 0x27051956    the U-Boot magic, little-endian (at +4, so it never
//                           collides with the big-endian uImage header at +0)
//   u32 dict_size           decoder window (64 KiB on observed devices)
//   u32 uncompressed_size   exact decoded size
//   .. jzlzma bitstream
//
// The bitstream is LZMA's match model with the entropy coder stripped out: raw
// LSB-first bits, no probabilities. Lengths use LZMA's three-band coding
// (2..9 / 10..17 / 18..273) and distances LZMA's 6-bit position-slot table with
// reversed extra bits (align-reversed for slots >= 14), plus a four-slot
// recent-distance (rep) cache with rep0/rep1/rep2/rep3 opcodes and a one-byte
// rep0 shortcut. There is no end-of-stream marker: the stream simply ends once
// uncompressed_size bytes are out, so decoding is bounded by that declared size
// (a reference Python decoder that instead ran to input exhaustion overran into
// the final byte's padding bits).
//
// Two container forms occur. The wrapped form above is detected by the `jzlzma`
// signature, anchored on the 0x27051956 magic. A bare stream led only by the
// 8-byte dict+uncompressed_size pair (newer T40/T41 parts, e.g. Wyze Cam v4) is
// magicless, checksumless and not entropy-coded, so it has no FP-safe standalone
// identity: low-entropy data trivially "decodes" to any declared size. It is
// therefore decoded only where a container points at it — a uImage whose
// ih_comp = lzma payload fails a standard-LZMA decode (see extract/uimage.cpp) —
// never by a standalone scan signature.
//
// Recovered from binwalk PR #957 and confirmed against two stock firmware
// images (cpio rootfs payloads that end cleanly at the declared size).
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ft {

// Sane ceiling on the header-declared uncompressed size (256 MiB), shared by
// the signature constraints, the validator and the extractor so none can be
// tricked into an unbounded allocation.
constexpr uint32_t kJzlzmaMaxOut = uint32_t(256) << 20;

// Decode the jzlzma bitstream in `stream` (the bytes after the 16-byte wrapper
// header, or after the 8-byte raw dict+size pair) to exactly `out_size` bytes.
// Returns nullopt on a truncated stream (input exhausted first) or a corrupt
// one (a distance reaching before the start of the output). `out_size` must be
// <= kJzlzmaMaxOut; the output buffer is reserved up front. When `consumed` is
// non-null it receives the number of input bytes the decode actually read —
// the stream self-terminates at out_size, so this locates the logical end of
// the bitstream inside a larger span (it includes the final opcode's bits, so
// it may overshoot by a few bits). With `allow_short`, a stream that runs out
// of input early returns what it produced so far instead of failing — for the
// padded-stream convention (declared size slightly beyond the real payload,
// Wyze Cam v4 T41 images over-declare by ~1 KiB of NUL-literal padding); the
// caller decides whether the shortfall is acceptable.
std::optional<std::vector<uint8_t>> jzlzma_decode(std::span<const uint8_t> stream, size_t out_size,
                                                  size_t* consumed = nullptr,
                                                  bool allow_short = false);

}  // namespace ft

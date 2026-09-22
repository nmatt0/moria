// decompress.hpp — the single seam where a codec library is called.
//
// Extraction logic (squashfs, later ext/cpio/...) never touches zlib/liblzma/etc
// directly; it asks this module to turn one compressed block into bytes. That
// keeps each codec a leaf dependency: if one ever misbehaves, swap the one
// function here for an internal implementation without touching format code.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ft {

// SquashFS compression IDs (also used generally). Values match the squashfs
// superblock `compression` field so a format can pass it straight through.
enum class Compressor : uint16_t {
    Unknown = 0,
    Gzip = 1,  // zlib stream (RFC1950), as squashfs uses it
    Lzma = 2,  // legacy standalone LZMA (rare)
    Lzo = 3,
    Xz = 4,   // .xz container stream
    Lz4 = 5,  // lz4 block (squashfs uses the legacy/frame form; see .cpp)
    Zstd = 6,
    Deflate = 7,  // raw DEFLATE, no zlib/gzip header (UBIFS zlib nodes) — not a squashfs id
    LzoRle = 8,   // LZO-RLE variant (f2fs lzo-rle): lzo1x with the zero-run extension
    Lz4Legacy = 9,  // LZ4 legacy frame (magic 0x184C2102) — Android ramdisks; not a squashfs id
};

const char* compressor_name(Compressor c);

// True if this build was compiled with support for the codec.
bool compressor_supported(Compressor c);

// Decompress `src` into a fresh buffer of at most `max_out` bytes.
// Returns nullopt on any failure: unsupported codec, corrupt stream, or output
// that would exceed max_out (a hostile header claiming a huge block). Never
// throws, never writes past max_out.
std::optional<std::vector<uint8_t>> decompress(Compressor c, std::span<const uint8_t> src,
                                               size_t max_out);

// Decompress an lz4 *block* to exactly `out_len` bytes. Unlike decompress(Lz4),
// this tolerates a compressed stream that would decode to more than out_len (an
// erofs pcluster whose final logical cluster is partial) by stopping early, and
// requires exactly out_len bytes to be produced. `src` is the raw block with any
// erofs leading zero-padding already stripped by the caller. Returns nullopt if
// out_len bytes cannot be produced or lz4 support was not compiled in.
std::optional<std::vector<uint8_t>> lz4_block_exact(std::span<const uint8_t> src, size_t out_len);

// Decompress an erofs "microlzma" pcluster to exactly `out_len` bytes. MicroLZMA
// is a headerless LZMA1 stream: the lc/lp/pb props are packed into the first byte
// and the dictionary size / uncompressed size come from the caller, not the
// stream (erofs passes an 8 MiB max dict and the exact decoded length). `src` is
// the raw block with any erofs leading zero-padding already stripped by the
// caller. Returns nullopt if out_len bytes cannot be produced or liblzma was not
// compiled in.
std::optional<std::vector<uint8_t>> microlzma_block_exact(std::span<const uint8_t> src,
                                                          size_t out_len);

// Decompress a UPX LZMA block to exactly `out_len` bytes. `src` is the raw LZMA1
// stream with the 2-byte UPX property header already stripped; `lc`/`lp`/`pb`
// are decoded from that header by the caller. Returns nullopt if out_len bytes
// cannot be produced or liblzma was not compiled in.
std::optional<std::vector<uint8_t>> upx_lzma_block_exact(std::span<const uint8_t> src,
                                                         size_t out_len, uint8_t lc, uint8_t lp,
                                                         uint8_t pb);

// Identify-time probe for a legacy standalone LZMA1 (".lzma alone") stream: the
// FP-proof gate for a magicless format. Decodes `src` with the .lzma-alone
// decoder, growing the output up to `out_cap` bytes, and succeeds ONLY if the
// stream reaches its encoded end-of-stream marker (LZMA_STREAM_END). A random
// header that happens to start `5D 00 00 ...` either errors in the range coder
// or runs out of input without a valid end marker, so it fails here. On success
// returns the decoded length and, via `in_consumed`, the exact compressed span
// (so a caller can claim the region and stop the scan past it). Returns nullopt
// on any decode error, on running out of input before the end marker, on
// hitting `out_cap` before the end marker, or if liblzma was not compiled in.
std::optional<uint64_t> lzma_alone_probe(std::span<const uint8_t> src, size_t out_cap,
                                         size_t* in_consumed = nullptr);

// Streaming decompression of a whole standalone stream/container whose decoded
// size is not known in advance (a gzip/xz/zstd/lz4-frame firmware wrapper). Grows
// the output buffer as it goes, stopping at `cap` bytes. Unlike decompress(),
// which expects one block and a known max, this consumes the entire stream.
// `c` must be Gzip (gzip OR zlib container, auto-detected), Xz, Zstd, or Lz4
// (frame format). Returns the decoded bytes, or nullopt on unsupported codec /
// corrupt stream. Trailing bytes after the first stream are ignored; when
// `in_consumed` is non-null it receives how many input bytes the stream actually
// spanned (so a caller can claim exactly that region), best-effort.
std::optional<std::vector<uint8_t>> decompress_stream(Compressor c, std::span<const uint8_t> src,
                                                      size_t cap, size_t* in_consumed = nullptr);

}  // namespace ft

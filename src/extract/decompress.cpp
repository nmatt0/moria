// decompress.cpp — codec leaf calls. Each MORIA_HAVE_* codec is one function;
// everything else reports unsupported. See decompress.hpp for the rationale.
#include "extract/decompress.hpp"

#include <cstdint>

#include "extract/lzo1x.hpp"  // internal LZO1X (MIT); no GPL liblzo2 dependency

#ifdef MORIA_HAVE_ZLIB
#include <zlib.h>
#endif
#ifdef MORIA_HAVE_LZMA
#include <lzma.h>
#endif
#ifdef MORIA_HAVE_LZ4
#include <lz4.h>
#include <lz4frame.h>
#endif
#ifdef MORIA_HAVE_ZSTD
#include <zstd.h>
#endif

namespace ft {

const char* compressor_name(Compressor c) {
    switch (c) {
        case Compressor::Gzip: return "gzip";
        case Compressor::Lzma: return "lzma";
        case Compressor::Lzo: return "lzo";
        case Compressor::LzoRle: return "lzo-rle";
        case Compressor::Xz: return "xz";
        case Compressor::Lz4: return "lz4";
        case Compressor::Lz4Legacy: return "lz4-legacy";
        case Compressor::Zstd: return "zstd";
        case Compressor::Deflate: return "deflate";
        case Compressor::Unknown: return "unknown";
    }
    return "unknown";
}

bool compressor_supported(Compressor c) {
    switch (c) {
#ifdef MORIA_HAVE_ZLIB
        case Compressor::Gzip: return true;
#endif
#ifdef MORIA_HAVE_LZMA
        case Compressor::Xz: return true;
        case Compressor::Lzma: return true;  // legacy .lzma alone (streaming path)
#endif
#ifdef MORIA_HAVE_LZ4
        case Compressor::Lz4: return true;
        case Compressor::Lz4Legacy: return true;
#endif
        case Compressor::Lzo: return true;  // internal lzo1x, always available
        case Compressor::LzoRle: return true;
#ifdef MORIA_HAVE_ZLIB
        case Compressor::Deflate: return true;
#endif
#ifdef MORIA_HAVE_ZSTD
        case Compressor::Zstd: return true;
#endif
        default: return false;
    }
}

namespace {

#ifdef MORIA_HAVE_ZLIB
// squashfs "gzip" is a zlib stream (RFC1950), not a gzip container.
std::optional<std::vector<uint8_t>> inflate_zlib(std::span<const uint8_t> src, size_t max_out) {
    std::vector<uint8_t> out(max_out);
    uLongf dst_len = static_cast<uLongf>(max_out);
    int rc = uncompress(out.data(), &dst_len, src.data(), static_cast<uLong>(src.size()));
    if (rc != Z_OK) return std::nullopt;
    out.resize(dst_len);
    return out;
}

// UBIFS "zlib" nodes are raw DEFLATE (no zlib/gzip header): windowBits = -15.
std::optional<std::vector<uint8_t>> inflate_raw_deflate(std::span<const uint8_t> src,
                                                        size_t max_out) {
    std::vector<uint8_t> out(max_out);
    z_stream s{};
    if (inflateInit2(&s, -15) != Z_OK) return std::nullopt;
    s.next_in = const_cast<Bytef*>(src.data());
    s.avail_in = static_cast<uInt>(src.size());
    s.next_out = out.data();
    s.avail_out = static_cast<uInt>(max_out);
    int rc = inflate(&s, Z_FINISH);
    size_t produced = max_out - s.avail_out;
    inflateEnd(&s);
    if (rc != Z_STREAM_END && rc != Z_OK && rc != Z_BUF_ERROR) return std::nullopt;
    out.resize(produced);
    return out;
}
#endif

#ifdef MORIA_HAVE_LZMA
std::optional<std::vector<uint8_t>> inflate_xz(std::span<const uint8_t> src, size_t max_out) {
    std::vector<uint8_t> out(max_out);
    uint64_t memlimit = UINT64_MAX;
    size_t in_pos = 0, out_pos = 0;
    lzma_ret rc = lzma_stream_buffer_decode(&memlimit, 0, nullptr, src.data(), &in_pos, src.size(),
                                            out.data(), &out_pos, out.size());
    if (rc != LZMA_OK) return std::nullopt;
    out.resize(out_pos);
    return out;
}

// Legacy standalone LZMA1 (.lzma): a 13-byte header (props + dict size + a
// declared uncompressed size) followed by the raw stream. Used as a single block
// by the non-standard "LZMA squashfs" that some vendors (Broadcom/TP-Link/OpenWrt)
// ship while leaving the superblock compression field as gzip.
std::optional<std::vector<uint8_t>> inflate_lzma_alone(std::span<const uint8_t> src, size_t max_out) {
    lzma_stream s = LZMA_STREAM_INIT;
    if (lzma_alone_decoder(&s, UINT64_MAX) != LZMA_OK) return std::nullopt;
    std::vector<uint8_t> out(max_out);
    s.next_in = src.data();
    s.avail_in = src.size();
    s.next_out = out.data();
    s.avail_out = out.size();
    lzma_ret rc = lzma_code(&s, LZMA_FINISH);
    size_t produced = out.size() - s.avail_out;
    lzma_end(&s);
    // Fully decoded, or filled the block cap exactly (declared size == max_out).
    if (rc != LZMA_STREAM_END && !(rc == LZMA_OK && s.avail_out == 0)) return std::nullopt;
    out.resize(produced);
    return out;
}
#endif

#ifdef MORIA_HAVE_LZ4
std::optional<std::vector<uint8_t>> inflate_lz4(std::span<const uint8_t> src, size_t max_out) {
    std::vector<uint8_t> out(max_out);
    int n = LZ4_decompress_safe(reinterpret_cast<const char*>(src.data()),
                                reinterpret_cast<char*>(out.data()), static_cast<int>(src.size()),
                                static_cast<int>(out.size()));
    if (n < 0) return std::nullopt;
    out.resize(static_cast<size_t>(n));
    return out;
}
#endif

#ifdef MORIA_HAVE_ZSTD
std::optional<std::vector<uint8_t>> inflate_zstd(std::span<const uint8_t> src, size_t max_out) {
    std::vector<uint8_t> out(max_out);
    size_t n = ZSTD_decompress(out.data(), out.size(), src.data(), src.size());
    if (ZSTD_isError(n)) return std::nullopt;
    out.resize(n);
    return out;
}
#endif

}  // namespace

std::optional<std::vector<uint8_t>> lz4_block_exact([[maybe_unused]] std::span<const uint8_t> src,
                                                   [[maybe_unused]] size_t out_len) {
#ifdef MORIA_HAVE_LZ4
    if (src.empty() || out_len == 0) return std::nullopt;
    std::vector<uint8_t> out(out_len);
    // safe_partial produces up to targetOutputSize bytes and tolerates an input
    // stream that would decode to more (partial final cluster of an erofs file).
    int n = LZ4_decompress_safe_partial(
        reinterpret_cast<const char*>(src.data()), reinterpret_cast<char*>(out.data()),
        static_cast<int>(src.size()), static_cast<int>(out_len), static_cast<int>(out_len));
    if (n < 0 || static_cast<size_t>(n) != out_len) return std::nullopt;
    return out;
#else
    return std::nullopt;
#endif
}

std::optional<std::vector<uint8_t>> microlzma_block_exact(
    [[maybe_unused]] std::span<const uint8_t> src, [[maybe_unused]] size_t out_len) {
#ifdef MORIA_HAVE_LZMA
    if (src.empty() || out_len == 0) return std::nullopt;
    // erofs Z_EROFS_LZMA_MAX_DICT_SIZE = 8 * 1 MiB pcluster max. The dict only
    // needs to be >= the true window, so the fixed max always suffices.
    constexpr uint32_t kDictSize = 8u * 1024u * 1024u;
    std::vector<uint8_t> out(out_len);
    lzma_stream s = LZMA_STREAM_INIT;
    // uncomp_size_is_exact = true: moria decodes each pcluster whole to its exact
    // logical length, so the decoder can stop precisely without an end marker.
    if (lzma_microlzma_decoder(&s, src.size(), out_len, /*uncomp_size_is_exact=*/1, kDictSize) !=
        LZMA_OK)
        return std::nullopt;
    s.next_in = src.data();
    s.avail_in = src.size();
    s.next_out = out.data();
    s.avail_out = out_len;
    lzma_ret rc = lzma_code(&s, LZMA_FINISH);
    const size_t produced = out_len - s.avail_out;
    lzma_end(&s);
    if (rc != LZMA_STREAM_END || produced != out_len) return std::nullopt;
    return out;
#else
    return std::nullopt;
#endif
}

namespace {

#ifdef MORIA_HAVE_ZLIB
// gzip OR zlib container, streamed to a growing buffer (windowBits 15+32 = auto).
std::optional<std::vector<uint8_t>> gunzip_stream(std::span<const uint8_t> src, size_t cap,
                                                  size_t* in_consumed) {
    z_stream s{};
    if (inflateInit2(&s, 15 + 32) != Z_OK) return std::nullopt;
    s.next_in = const_cast<Bytef*>(src.data());
    s.avail_in = static_cast<uInt>(src.size());
    std::vector<uint8_t> out;
    int rc = Z_OK;
    while (rc != Z_STREAM_END) {
        const size_t old = out.size();
        if (old >= cap) break;
        const size_t grow = std::min<size_t>(1u << 20, cap - old);
        out.resize(old + grow);
        s.next_out = out.data() + old;
        s.avail_out = static_cast<uInt>(grow);
        rc = inflate(&s, Z_NO_FLUSH);
        out.resize(old + (grow - s.avail_out));
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK) { inflateEnd(&s); return std::nullopt; }
        if (s.avail_out != 0 && s.avail_in == 0) break;  // ran out of input
    }
    if (in_consumed) *in_consumed = src.size() - s.avail_in;
    inflateEnd(&s);
    return out;
}
#endif

#ifdef MORIA_HAVE_LZMA
// Shared streaming loop for an already-initialized lzma decoder.
std::optional<std::vector<uint8_t>> lzma_run(lzma_stream& s, size_t cap, size_t src_size,
                                            size_t* in_consumed) {
    std::vector<uint8_t> out;
    lzma_ret rc = LZMA_OK;
    while (rc != LZMA_STREAM_END) {
        const size_t old = out.size();
        if (old >= cap) break;
        const size_t grow = std::min<size_t>(1u << 20, cap - old);
        out.resize(old + grow);
        s.next_out = out.data() + old;
        s.avail_out = grow;
        rc = lzma_code(&s, LZMA_FINISH);
        out.resize(old + (grow - s.avail_out));
        if (rc == LZMA_STREAM_END) break;
        if (rc != LZMA_OK) { lzma_end(&s); return std::nullopt; }
        if (s.avail_out != 0 && s.avail_in == 0) break;
    }
    if (in_consumed) *in_consumed = src_size - s.avail_in;
    lzma_end(&s);
    return out;
}

// Legacy .lzma "alone" format (U-Boot uImage lzma payloads).
std::optional<std::vector<uint8_t>> unlzma_alone(std::span<const uint8_t> src, size_t cap,
                                                 size_t* in_consumed) {
    lzma_stream s = LZMA_STREAM_INIT;
    if (lzma_alone_decoder(&s, UINT64_MAX) != LZMA_OK) return std::nullopt;
    s.next_in = src.data();
    s.avail_in = src.size();
    return lzma_run(s, cap, src.size(), in_consumed);
}

std::optional<std::vector<uint8_t>> unxz_stream(std::span<const uint8_t> src, size_t cap,
                                                size_t* in_consumed) {
    lzma_stream s = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&s, UINT64_MAX, 0) != LZMA_OK) return std::nullopt;
    s.next_in = src.data();
    s.avail_in = src.size();
    return lzma_run(s, cap, src.size(), in_consumed);
}
#endif

#ifdef MORIA_HAVE_ZSTD
std::optional<std::vector<uint8_t>> unzstd_stream(std::span<const uint8_t> src, size_t cap,
                                                  size_t* in_consumed) {
    ZSTD_DStream* ds = ZSTD_createDStream();
    if (!ds) return std::nullopt;
    ZSTD_initDStream(ds);
    ZSTD_inBuffer in{src.data(), src.size(), 0};
    std::vector<uint8_t> out;
    while (in.pos < in.size) {
        const size_t old = out.size();
        if (old >= cap) break;
        const size_t grow = std::min<size_t>(1u << 20, cap - old);
        out.resize(old + grow);
        ZSTD_outBuffer ob{out.data() + old, grow, 0};
        size_t rc = ZSTD_decompressStream(ds, &ob, &in);
        out.resize(old + ob.pos);
        if (ZSTD_isError(rc)) { ZSTD_freeDStream(ds); return std::nullopt; }
        if (rc == 0) break;  // frame complete
        if (ob.pos == 0 && in.pos == in.size) break;
    }
    if (in_consumed) *in_consumed = in.pos;
    ZSTD_freeDStream(ds);
    return out;
}
#endif

#ifdef MORIA_HAVE_LZ4
std::optional<std::vector<uint8_t>> unlz4_frame(std::span<const uint8_t> src, size_t cap,
                                               size_t* in_consumed) {
    LZ4F_dctx* dctx = nullptr;
    if (LZ4F_isError(LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION))) return std::nullopt;
    std::vector<uint8_t> out;
    size_t in_pos = 0;
    for (;;) {
        const size_t old = out.size();
        if (old >= cap) break;
        const size_t grow = std::min<size_t>(1u << 20, cap - old);
        out.resize(old + grow);
        size_t dst_size = grow;
        size_t src_size = src.size() - in_pos;
        size_t rc = LZ4F_decompress(dctx, out.data() + old, &dst_size, src.data() + in_pos,
                                    &src_size, nullptr);
        out.resize(old + dst_size);
        in_pos += src_size;
        if (LZ4F_isError(rc)) { LZ4F_freeDecompressionContext(dctx); return std::nullopt; }
        if (rc == 0) break;  // frame complete
        if (dst_size == 0 && src_size == 0) break;
    }
    if (in_consumed) *in_consumed = in_pos;
    LZ4F_freeDecompressionContext(dctx);
    return out;
}

// LZ4 legacy frame (magic 0x184C2102), the pre-frame-spec format still used for
// Android boot/init_boot/vendor_boot ramdisks. Layout: the 4-byte magic, then a
// sequence of [u32 LE compressed_block_size][compressed block] to EOF. Each block
// decompresses to at most 8 MiB (the legacy fixed block size). There is no end
// marker, so we stop at EOF, at a value that is itself a frame magic (a
// concatenated stream), or at the first implausible/undecodable block — keeping
// whatever decoded so far.
std::optional<std::vector<uint8_t>> unlz4_legacy(std::span<const uint8_t> src, size_t cap,
                                                 size_t* in_consumed) {
    constexpr uint32_t kLegacyMagic = 0x184C2102u;
    constexpr uint32_t kFrameMagic = 0x184D2204u;
    constexpr size_t kLegacyBlockMax = 8u * 1024 * 1024;  // legacy uncompressed block size
    auto rd32 = [](const uint8_t* p) {
        return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
    };
    if (src.size() < 8 || rd32(src.data()) != kLegacyMagic) return std::nullopt;

    std::vector<uint8_t> out;
    std::vector<uint8_t> block(kLegacyBlockMax);
    size_t pos = 4;
    while (pos + 4 <= src.size() && out.size() < cap) {
        uint32_t bs = rd32(src.data() + pos);
        // A new frame magic (legacy or modern) or a skippable-frame magic marks the
        // end of this stream (concatenated frames), not a block size.
        if (bs == kLegacyMagic || bs == kFrameMagic || (bs & 0xFFFFFFF0u) == 0x184D2A50u) break;
        if (bs == 0 || bs > src.size() - (pos + 4)) break;  // truncated / not a real block
        int n = LZ4_decompress_safe(reinterpret_cast<const char*>(src.data() + pos + 4),
                                    reinterpret_cast<char*>(block.data()), static_cast<int>(bs),
                                    static_cast<int>(block.size()));
        if (n < 0) break;  // corrupt block: keep what we have
        size_t take = std::min<size_t>(static_cast<size_t>(n), cap - out.size());
        out.insert(out.end(), block.begin(), block.begin() + take);
        pos += 4 + bs;
        if (take < static_cast<size_t>(n)) break;  // hit the cap mid-block
    }
    if (out.empty()) return std::nullopt;
    if (in_consumed) *in_consumed = pos;
    return out;
}
#endif

}  // namespace

std::optional<std::vector<uint8_t>> decompress_stream([[maybe_unused]] Compressor c,
                                                      [[maybe_unused]] std::span<const uint8_t> src,
                                                      [[maybe_unused]] size_t cap,
                                                      [[maybe_unused]] size_t* in_consumed) {
    if (in_consumed) *in_consumed = 0;
    if (src.empty() || cap == 0) return std::nullopt;
    switch (c) {
#ifdef MORIA_HAVE_ZLIB
        case Compressor::Gzip: return gunzip_stream(src, cap, in_consumed);
#endif
#ifdef MORIA_HAVE_LZMA
        case Compressor::Xz: return unxz_stream(src, cap, in_consumed);
        case Compressor::Lzma: return unlzma_alone(src, cap, in_consumed);
#endif
#ifdef MORIA_HAVE_ZSTD
        case Compressor::Zstd: return unzstd_stream(src, cap, in_consumed);
#endif
#ifdef MORIA_HAVE_LZ4
        case Compressor::Lz4: return unlz4_frame(src, cap, in_consumed);
        case Compressor::Lz4Legacy: return unlz4_legacy(src, cap, in_consumed);
#endif
        default: return std::nullopt;
    }
}

std::optional<std::vector<uint8_t>> decompress(Compressor c, std::span<const uint8_t> src,
                                               size_t max_out) {
    if (src.empty() || max_out == 0) return std::nullopt;
    switch (c) {
#ifdef MORIA_HAVE_ZLIB
        case Compressor::Gzip: return inflate_zlib(src, max_out);
        case Compressor::Deflate: return inflate_raw_deflate(src, max_out);
#endif
#ifdef MORIA_HAVE_LZMA
        case Compressor::Xz: return inflate_xz(src, max_out);
        case Compressor::Lzma: return inflate_lzma_alone(src, max_out);
#endif
#ifdef MORIA_HAVE_LZ4
        case Compressor::Lz4: return inflate_lz4(src, max_out);
#endif
#ifdef MORIA_HAVE_ZSTD
        case Compressor::Zstd: return inflate_zstd(src, max_out);
#endif
        case Compressor::Lzo:
        case Compressor::LzoRle: {
            std::vector<uint8_t> out(max_out);
            size_t got = 0;
            if (!lzo1x_decompress_safe(src.data(), src.size(), out.data(), out.size(), &got,
                                       /*rle=*/c == Compressor::LzoRle))
                return std::nullopt;
            out.resize(got);
            return out;
        }
        default: return std::nullopt;
    }
}

}  // namespace ft

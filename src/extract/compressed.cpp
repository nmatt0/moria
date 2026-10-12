// compressed.cpp — standalone compressed-stream extraction. See compressed.hpp.
#include "extract/compressed.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "extract/decompress.hpp"
#include "extract/jzlzma.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint64_t MAX_OUT = uint64_t(8) << 30;  // decompressed-size cap

std::optional<Compressor> codec_for(const std::string& type) {
    if (type == "gzip") return Compressor::Gzip;
    if (type == "xz") return Compressor::Xz;
    if (type == "lzma") return Compressor::Lzma;
    if (type == "zstd") return Compressor::Zstd;
    if (type == "lz4") return Compressor::Lz4;
    if (type == "lz4_legacy") return Compressor::Lz4Legacy;
    return std::nullopt;
}

}  // namespace

bool extract_compressed(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                        Extracted& out) {
    out.offset = f.offset;
    out.type = f.type;
    out.root = subdir;

    auto codec = codec_for(f.type);
    if (!codec || !compressor_supported(*codec)) {
        out.status = "unsupported:" + f.type;
        return true;
    }
    // Always feed the decoder from the finding offset to EOF: a stream format
    // carries no length in its header, so size inference can wrongly truncate the
    // span at a signature that (like a barely-compressible payload's residual
    // magic) appears *inside* the compressed data. The streaming decoder stops at
    // the true end of the stream and ignores trailing bytes, so reading past the
    // stream is harmless; `in_consumed` then tells us its real length.
    if (f.offset >= r.size()) {
        out.status = "error:empty";
        return true;
    }
    auto src = r.bytes(static_cast<size_t>(f.offset), static_cast<size_t>(r.size() - f.offset));
    if (!src) {
        out.status = "error:read";
        return true;
    }
    size_t consumed = 0;
    auto data = decompress_stream(*codec, *src, MAX_OUT, &consumed);
    if (!data || data->empty()) {
        out.status = "error:decompress";
        return true;
    }
    out.consumed = consumed;  // the true compressed span, so the driver can claim it
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    if (root.write_file(subdir + "/decompressed", *data, 0644)) {
        out.files++;
        out.bytes += data->size();
        out.status = "ok";
    } else {
        out.status = "error:write";
    }
    return true;
}

bool extract_jzlzma(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out) {
    out.offset = f.offset;
    out.type = "jzlzma";
    out.root = subdir;

    // mark_rootfs_lzma header: [payload_size u32][magic u32][dict u32][usize u32]
    auto payload_size = r.at<uint32_t>(f.offset, Endian::Little);
    auto uncomp = r.at<uint32_t>(f.offset + 12, Endian::Little);
    if (!payload_size || !uncomp || *uncomp > kJzlzmaMaxOut) {
        out.status = "error:read";
        return true;
    }
    const size_t stream_off = f.offset + 16;
    if (stream_off >= r.size()) {
        out.status = "error:read";
        return true;
    }
    // Decode from the declared span; a stream shorter than the file (a dump
    // padded past the payload) or clipped by EOF both decode the same.
    const size_t stream_len =
        std::min<size_t>(*payload_size, static_cast<size_t>(r.size() - stream_off));
    auto src = r.bytes(stream_off, stream_len);
    if (!src) {
        out.status = "error:read";
        return true;
    }
    auto data = jzlzma_decode(*src, *uncomp);
    if (!data || data->empty()) {
        out.status = "error:decompress";
        return true;
    }
    out.consumed = 16 + stream_len;
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    if (root.write_file(subdir + "/decompressed", *data, 0644)) {
        out.files++;
        out.bytes += data->size();
        out.status = "ok";
    } else {
        out.status = "error:write";
    }
    return true;
}

bool extract_jzlzma_raw(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                        Extracted& out) {
    out.offset = f.offset;
    out.type = "jzlzma-raw";
    out.root = subdir;

    // Raw header: [dict_size u32][uncomp_size u32], then the bitstream.
    auto uncomp = r.at<uint32_t>(f.offset + 4, Endian::Little);
    if (!uncomp || *uncomp > kJzlzmaMaxOut) {
        out.status = "error:read";
        return true;
    }
    const size_t stream_off = f.offset + 8;
    if (stream_off >= r.size()) {
        out.status = "error:read";
        return true;
    }
    // Decode from everything to EOF; the stream ends at its declared size, so
    // trailing data in the container is simply not consumed.
    const size_t span = static_cast<size_t>(r.size() - stream_off);
    auto src = r.bytes(stream_off, span);
    if (!src) {
        out.status = "error:read";
        return true;
    }
    size_t consumed = 0;
    auto data = jzlzma_decode(*src, *uncomp, &consumed);
    if ((!data || data->empty()) && *uncomp >= 4096) {
        // Padded-stream convention (T41 images over-declare by ~1 KiB): accept
        // a short decode covering >= 90% of the declared size.
        data = jzlzma_decode(*src, *uncomp, &consumed, /*allow_short=*/true);
        if (data && (data->size() < (*uncomp * 9) / 10)) data.reset();
    }
    if (!data || data->empty()) {
        out.status = "error:decompress";
        return true;
    }
    out.consumed = 8 + consumed;
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    if (root.write_file(subdir + "/decompressed", *data, 0644)) {
        out.files++;
        out.bytes += data->size();
        out.status = "ok";
    } else {
        out.status = "error:write";
    }
    return true;
}

}  // namespace ft

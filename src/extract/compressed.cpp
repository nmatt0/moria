// compressed.cpp — standalone compressed-stream extraction. See compressed.hpp.
#include "extract/compressed.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "extract/decompress.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint64_t MAX_OUT = uint64_t(8) << 30;  // decompressed-size cap

std::optional<Compressor> codec_for(const std::string& type) {
    if (type == "gzip") return Compressor::Gzip;
    if (type == "xz") return Compressor::Xz;
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

}  // namespace ft

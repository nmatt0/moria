// uimage.cpp — U-Boot legacy uImage payload extraction. See uimage.hpp.
//
// Header (64 bytes, big-endian): magic@0 (0x27051956), ih_size@12 (payload
// bytes), ih_comp@31 (0 none, 1 gzip, 2 bzip2, 3 lzma, 4 lzo, 5 lz4, 6 zstd),
// ih_name@32 (32 bytes). Payload starts at offset 64.
#include "extract/uimage.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "extract/decompress.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint64_t HEADER_SIZE = 64;
constexpr uint64_t MAX_PAYLOAD = uint64_t(8) << 30;

// ih_comp -> codec (or nullopt for "stored", -1 sentinel handled by caller).
enum { COMP_NONE = 0, COMP_GZIP = 1, COMP_BZIP2 = 2, COMP_LZMA = 3, COMP_LZO = 4, COMP_LZ4 = 5, COMP_ZSTD = 6 };

}  // namespace

bool extract_uimage(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out) {
    out.offset = f.offset;
    out.type = "uimage";
    out.root = subdir;
    const uint64_t base = f.offset;

    auto magic = r.at<uint32_t>(base, Endian::Big);
    auto size = r.at<uint32_t>(base + 12, Endian::Big);
    auto comp_b = r.bytes(base + 31, 1);
    if (!magic || *magic != 0x27051956 || !size || !comp_b) {
        out.status = "error:bad-header";
        return true;
    }
    const uint8_t comp = (*comp_b)[0];
    const uint64_t psize = std::min<uint64_t>(*size, MAX_PAYLOAD);
    if (psize == 0) {
        out.status = "error:empty";
        return true;
    }
    auto src = r.bytes(static_cast<size_t>(base + HEADER_SIZE), static_cast<size_t>(psize));
    if (!src) {
        out.status = "error:truncated";
        return true;
    }

    std::vector<uint8_t> data;
    bool ok = false;
    if (comp == COMP_NONE) {
        data.assign(src->begin(), src->end());
        ok = true;
    } else {
        std::optional<Compressor> codec;
        switch (comp) {
            case COMP_GZIP: codec = Compressor::Gzip; break;
            case COMP_LZMA: codec = Compressor::Lzma; break;
            case COMP_LZ4: codec = Compressor::Lz4; break;
            case COMP_ZSTD: codec = Compressor::Zstd; break;
            default: break;  // bzip2 / lzo: not wired here
        }
        if (codec && compressor_supported(*codec)) {
            if (auto d = decompress_stream(*codec, *src, MAX_PAYLOAD)) {
                data = std::move(*d);
                ok = !data.empty();
            }
        }
        if (!ok) {
            // Could not decompress (unsupported/other codec): keep the raw payload
            // so nothing is lost; a follow-up moria run can identify it.
            data.assign(src->begin(), src->end());
            out.warnings.push_back(
                "kept the compressed contents unchanged because they could not be unpacked");
        }
    }

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    if (root.write_file(subdir + "/payload", data, 0644)) {
        out.files++;
        out.bytes += data.size();
        out.status = ok ? "ok" : "partial";
    } else {
        out.status = "error:write";
    }
    return true;
}

}  // namespace ft

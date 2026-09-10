// android_sparse.cpp — unsparse + inner-FS extraction. See android_sparse.hpp.
//
// Header (little-endian): magic 0xed26ff3a @0, file_hdr_sz @8 (u16), chunk_hdr_sz
// @10 (u16), blk_sz @12, total_blks @16, total_chunks @20. Each chunk header:
// chunk_type @0 (0xCAC1 RAW / 0xCAC2 FILL / 0xCAC3 DONT_CARE / 0xCAC4 CRC),
// chunk_sz @4 (output blocks), total_sz @8 (bytes incl. header). The raw image
// is written to a sparse unsparsed.img (DONT_CARE and zero-FILL left as holes),
// then if it starts with an ext superblock the ext extractor is run on it.
#include "extract/android_sparse.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "extract/erofs.hpp"
#include "extract/ext.hpp"
#include "extract/safepath.hpp"
#include "file_map.hpp"

namespace ft {

namespace {

constexpr uint32_t SPARSE_MAGIC = 0xed26ff3a;
constexpr uint16_t CHUNK_RAW = 0xcac1;
constexpr uint16_t CHUNK_FILL = 0xcac2;
constexpr uint16_t CHUNK_DONTCARE = 0xcac3;
constexpr uint16_t CHUNK_CRC = 0xcac4;

constexpr uint64_t MAX_IMAGE = uint64_t(64) << 30;   // reject absurd headers
constexpr uint64_t MAX_FILL_BYTES = uint64_t(1) << 30;
constexpr uint32_t MAX_CHUNKS = 10000000;

bool write_at(int fd, uint64_t off, const uint8_t* data, size_t len) {
    while (len) {
        ssize_t n = ::pwrite(fd, data, len, static_cast<off_t>(off));
        if (n <= 0) return false;
        off += static_cast<uint64_t>(n);
        data += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

}  // namespace

bool extract_android_sparse(const Reader& r, const Finding& f, SafeRoot& root,
                            const std::string& subdir, Extracted& out) {
    out.offset = f.offset;
    out.type = "android_sparse";
    out.root = subdir;

    auto magic = r.at<uint32_t>(f.offset, Endian::Little);
    auto file_hdr = r.at<uint16_t>(f.offset + 8, Endian::Little);
    auto chunk_hdr = r.at<uint16_t>(f.offset + 10, Endian::Little);
    auto blk_sz = r.at<uint32_t>(f.offset + 12, Endian::Little);
    auto total_blks = r.at<uint32_t>(f.offset + 16, Endian::Little);
    auto total_chunks = r.at<uint32_t>(f.offset + 20, Endian::Little);
    if (!magic || *magic != SPARSE_MAGIC || !file_hdr || !chunk_hdr || !blk_sz || !total_blks ||
        !total_chunks) {
        out.status = "error:bad-header";
        return true;
    }
    if (*blk_sz == 0 || *blk_sz % 4 != 0 || *chunk_hdr < 12) {
        out.status = "error:bad-header";
        return true;
    }
    const uint64_t total = uint64_t(*total_blks) * *blk_sz;
    if (total == 0 || total > MAX_IMAGE || *total_chunks > MAX_CHUNKS) {
        out.status = "error:implausible-size";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    const std::string img_path = root.path() + "/" + subdir + "/unsparsed.img";
    int fd = ::open(img_path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        out.status = "error:create-img";
        return true;
    }
    bool truncated = false;
    if (::ftruncate(fd, static_cast<off_t>(total)) != 0) truncated = true;  // sparse

    uint64_t pos = f.offset + *file_hdr;
    uint64_t out_off = 0;
    const uint64_t end = r.size();
    for (uint32_t i = 0; i < *total_chunks && pos + *chunk_hdr <= end; ++i) {
        auto ctype = r.at<uint16_t>(pos, Endian::Little);
        auto csz = r.at<uint32_t>(pos + 4, Endian::Little);
        auto tsz = r.at<uint32_t>(pos + 8, Endian::Little);
        if (!ctype || !csz || !tsz) { truncated = true; break; }
        const uint64_t expand = uint64_t(*csz) * *blk_sz;
        const uint64_t data_off = pos + *chunk_hdr;
        if (out_off + expand > total) { truncated = true; break; }

        if (*ctype == CHUNK_RAW) {
            auto d = r.bytes(static_cast<size_t>(data_off), static_cast<size_t>(expand));
            if (!d) { truncated = true; break; }
            if (!write_at(fd, out_off, d->data(), d->size())) truncated = true;
        } else if (*ctype == CHUNK_FILL) {
            auto fill = r.at<uint32_t>(data_off, Endian::Little);
            if (fill && *fill != 0 && expand <= MAX_FILL_BYTES) {
                std::vector<uint8_t> buf(static_cast<size_t>(std::min<uint64_t>(expand, 1u << 20)));
                for (size_t j = 0; j + 4 <= buf.size(); j += 4) std::memcpy(&buf[j], &*fill, 4);
                uint64_t left = expand, o = out_off;
                while (left) {
                    size_t n = static_cast<size_t>(std::min<uint64_t>(left, buf.size()));
                    n &= ~size_t(3);
                    if (n == 0) break;
                    if (!write_at(fd, o, buf.data(), n)) { truncated = true; break; }
                    o += n;
                    left -= n;
                }
            }
            // zero fill or DONT_CARE-equivalent: leave the hole.
        } else if (*ctype == CHUNK_DONTCARE || *ctype == CHUNK_CRC) {
            // hole (already zero) / checksum: nothing to write.
        } else {
            truncated = true;
        }
        out_off += expand;
        pos += *tsz;
    }
    ::close(fd);
    out.consumed = pos - f.offset;  // input bytes the sparse stream occupied

    // If the reconstructed image is a filesystem we can read (ext or erofs, the
    // two inner formats Android sparse images wrap), extract it too.
    size_t inner_files = 0;
    FileMap fm;
    if (fm.open(img_path)) {
        Reader inner(fm.span());
        auto ext_magic = inner.at<uint16_t>(0x438, Endian::Little);       // ext s_magic 0xEF53
        auto erofs_magic = inner.at<uint32_t>(1024, Endian::Little);      // erofs @1024
        const std::string fs_sub = subdir + "/fs";
        Finding inner_f;
        inner_f.offset = 0;
        Extracted e2;
        bool ran = false;
        if (ext_magic && *ext_magic == 0xEF53 && root.make_dir(fs_sub)) {
            inner_f.type = "ext";
            extract_ext(inner, inner_f, root, fs_sub, e2);
            ran = true;
        } else if (erofs_magic && *erofs_magic == 0xE0F5E1E2 && root.make_dir(fs_sub)) {
            inner_f.type = "erofs";
            extract_erofs(inner, inner_f, root, fs_sub, e2);
            ran = true;
        }
        if (ran) {
            out.files += e2.files;
            out.dirs += e2.dirs;
            out.symlinks += e2.symlinks;
            out.bytes += e2.bytes;
            inner_files = e2.files;
            for (auto& w : e2.warnings) out.warnings.push_back("file system: " + w);
            if (e2.status == "partial") truncated = true;
        }
    }
    if (inner_files == 0)
        out.warnings.push_back("file system inside the image was not unpacked automatically; "
                               "see unsparsed.img");

    out.status = truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

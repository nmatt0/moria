// zip.cpp — ZIP extraction. See zip.hpp.
#include "extract/zip.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "extract/decompress.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint16_t METHOD_STORE = 0;
constexpr uint16_t METHOD_DEFLATE = 8;
constexpr uint16_t METHOD_BZIP2 = 12;
constexpr uint16_t METHOD_LZMA = 14;
constexpr uint16_t METHOD_ZSTD = 93;
constexpr uint16_t METHOD_XZ = 95;

constexpr uint16_t FLAG_ENCRYPTED = 0x0001;

constexpr uint32_t S_IFMT_ = 0170000;
constexpr uint32_t S_IFLNK_ = 0120000;

constexpr size_t MAX_MEMBERS = 200000;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;

std::optional<uint32_t> u32(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Little); }
std::optional<uint16_t> u16(const Reader& r, uint64_t o) { return r.at<uint16_t>(o, Endian::Little); }
std::optional<uint64_t> u64(const Reader& r, uint64_t o) { return r.at<uint64_t>(o, Endian::Little); }

// Read the zip64 extended-info extra field, patching sizes that were 0xFFFFFFFF
// in the 32-bit fields. Fields appear in a fixed order, present only when their
// 32-bit counterpart was max.
void apply_zip64(const Reader& r, uint64_t extra_off, uint16_t extra_len, uint64_t& uncomp,
                 uint64_t& comp, uint64_t& local_off) {
    uint64_t p = extra_off;
    const uint64_t end = extra_off + extra_len;
    while (p + 4 <= end) {
        auto id = u16(r, p);
        auto sz = u16(r, p + 2);
        if (!id || !sz) break;
        if (*id == 0x0001) {  // zip64 extended information
            uint64_t q = p + 4;
            const uint64_t fend = std::min<uint64_t>(end, q + *sz);
            if (uncomp == 0xFFFFFFFFu && q + 8 <= fend) { uncomp = u64(r, q).value_or(uncomp); q += 8; }
            if (comp == 0xFFFFFFFFu && q + 8 <= fend) { comp = u64(r, q).value_or(comp); q += 8; }
            if (local_off == 0xFFFFFFFFu && q + 8 <= fend) { local_off = u64(r, q).value_or(local_off); q += 8; }
            return;
        }
        p += 4 + *sz;
    }
}

// Locate the End Of Central Directory record (scan back from EOF for PK\5\6).
std::optional<uint64_t> find_eocd(const Reader& r, uint64_t base) {
    static const std::vector<uint8_t> EOCD = {0x50, 0x4B, 0x05, 0x06};
    const uint64_t filesz = r.size();
    uint64_t start = (filesz > base + 66000) ? filesz - 66000 : base;
    std::optional<uint64_t> found;
    for (uint64_t i = start; i + 22 <= filesz; ++i)
        if (r.matches_at(i, EOCD)) found = i;  // last match wins (trailing data)
    return found;
}

}  // namespace

bool extract_zip(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.offset = f.offset;
    out.type = "zip";
    out.root = subdir;
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    const uint64_t base = f.offset;
    auto eocd = find_eocd(r, base);
    if (!eocd) {
        out.status = "error:no-eocd";
        return true;
    }
    // Central directory location. zip64 locator (PK\6\7) precedes the EOCD when
    // the archive is large; fall back to it if the 32-bit offset is max.
    auto cd_count16 = u16(r, *eocd + 10);
    auto cd_off32 = u32(r, *eocd + 16);
    if (!cd_off32) {
        out.status = "error:bad-eocd";
        return true;
    }
    uint64_t cd_off = *cd_off32;
    static const std::vector<uint8_t> Z64LOC = {0x50, 0x4B, 0x06, 0x07};
    if (cd_off == 0xFFFFFFFFu && *eocd >= 20 && r.matches_at(*eocd - 20, Z64LOC)) {
        auto z64eocd = u64(r, *eocd - 20 + 8);
        if (z64eocd) {
            auto o = u64(r, base + *z64eocd + 48);  // cd offset in zip64 EOCD
            if (o) cd_off = *o;
        }
    }

    bool truncated = false;
    uint64_t pos = base + cd_off;
    const uint64_t filesz = r.size();
    static const std::vector<uint8_t> CDH = {0x50, 0x4B, 0x01, 0x02};
    size_t seen = 0;
    while (pos + 46 <= filesz && r.matches_at(pos, CDH)) {
        if (seen++ > MAX_MEMBERS) { truncated = true; break; }
        auto flags = u16(r, pos + 8);
        auto method = u16(r, pos + 10);
        auto comp32 = u32(r, pos + 20);
        auto uncomp32 = u32(r, pos + 24);
        auto namelen = u16(r, pos + 28);
        auto extralen = u16(r, pos + 30);
        auto commentlen = u16(r, pos + 32);
        auto ext_attrs = u32(r, pos + 38);
        auto local_off32 = u32(r, pos + 42);
        if (!flags || !method || !comp32 || !uncomp32 || !namelen || !extralen || !commentlen ||
            !ext_attrs || !local_off32)
            break;

        std::string name;
        if (auto nb = r.bytes(pos + 46, *namelen)) name.assign(nb->begin(), nb->end());
        uint64_t uncomp = *uncomp32, comp = *comp32, local_off = *local_off32;
        apply_zip64(r, pos + 46 + *namelen, *extralen, uncomp, comp, local_off);
        const uint64_t next = pos + 46 + *namelen + *extralen + *commentlen;
        pos = next;

        if (name.empty() || name.find("..") != std::string::npos) continue;
        const bool is_dir = name.back() == '/';
        const std::string full = subdir + "/" + name;
        const uint32_t mode = (*ext_attrs >> 16) & 0xffff;

        if (is_dir) {
            std::string d = full;
            if (!d.empty() && d.back() == '/') d.pop_back();
            if (root.make_dir(d)) out.dirs++;
            continue;
        }
        if (*flags & FLAG_ENCRYPTED) {
            out.warnings.push_back("skipped encrypted file: " + name);
            truncated = true;
            continue;
        }
        if (uncomp > MAX_FILE_BYTES) { truncated = true; continue; }

        // Data starts past the local file header (its name/extra lengths may
        // differ from the central directory's).
        auto lnamelen = u16(r, base + local_off + 26);
        auto lextralen = u16(r, base + local_off + 28);
        if (!lnamelen || !lextralen) { truncated = true; continue; }
        const uint64_t data_off = base + local_off + 30 + *lnamelen + *lextralen;
        auto src = r.bytes(static_cast<size_t>(data_off), static_cast<size_t>(comp));
        if (!src) { truncated = true; continue; }

        std::vector<uint8_t> data;
        bool ok = false;
        if (*method == METHOD_STORE) {
            data.assign(src->begin(), src->end());
            ok = data.size() == uncomp;
        } else if (*method == METHOD_DEFLATE) {
            if (auto d = decompress(Compressor::Deflate, *src, static_cast<size_t>(uncomp))) {
                data = std::move(*d);
                ok = data.size() == uncomp;
            }
        } else if (*method == METHOD_XZ) {
            if (auto d = decompress(Compressor::Xz, *src, static_cast<size_t>(uncomp))) { data = std::move(*d); ok = data.size() == uncomp; }
        } else if (*method == METHOD_ZSTD) {
            if (auto d = decompress(Compressor::Zstd, *src, static_cast<size_t>(uncomp))) { data = std::move(*d); ok = data.size() == uncomp; }
        } else {
            out.warnings.push_back("compression method " + std::to_string(*method) +
                                   " is not supported: " + name);
            truncated = true;
            continue;
        }
        if (!ok) { truncated = true; continue; }

        if ((mode & S_IFMT_) == S_IFLNK_) {
            std::string target(data.begin(), data.end());
            if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
            if (!target.empty() && root.make_symlink(full, target)) out.symlinks++;
            continue;
        }
        const uint32_t perms = (mode & 0777) ? (mode & 0777) : 0644;
        if (root.write_file(full, data, perms)) {
            out.files++;
            out.bytes += data.size();
        } else {
            out.warnings.push_back("write failed: " + name);
        }
    }

    (void)cd_count16;
    out.status = truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

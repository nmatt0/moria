// uimage.cpp — U-Boot legacy uImage refinement validator.
// Header is 64 bytes, all big-endian:
//   magic u32@0, hcrc u32@4, time u32@8, size u32@12, load u32@16, ep u32@20,
//   dcrc u32@24, os u8@28, arch u8@29, type u8@30, comp u8@31, name char[32]@32.
// hcrc is the CRC32 of the 64-byte header with the hcrc field zeroed.
#include "validators/uimage.hpp"

#include <array>
#include <cstring>
#include <string>

#include "crc32.hpp"

namespace ft {

namespace {
uint64_t field(const FieldMap& f, const char* k) {
    auto it = f.find(k);
    return it == f.end() ? 0 : it->second;
}

const char* arch_name(uint64_t a) {
    switch (a) {
        case 2: return "arm";
        case 3: return "x86";
        case 5: return "mips";
        case 8: return "mips64";
        case 20: return "arm64";
        case 22: return "riscv";
        case 4: return "ia64";
        case 7: return "ppc";
        default: return nullptr;
    }
}

const char* comp_name(uint64_t c) {
    switch (c) {
        case 0: return "none";
        case 1: return "gzip";
        case 2: return "bzip2";
        case 3: return "lzma";
        case 4: return "lzo";
        case 5: return "lz4";
        case 6: return "zstd";
        default: return nullptr;
    }
}
}  // namespace

bool validate_uimage(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    auto hdr = r.bytes(off, 64);
    if (!hdr) return false;

    // Recompute header CRC with the hcrc field (bytes 4..8) zeroed.
    std::array<uint8_t, 64> tmp{};
    std::memcpy(tmp.data(), hdr->data(), 64);
    tmp[4] = tmp[5] = tmp[6] = tmp[7] = 0;
    const uint32_t want = static_cast<uint32_t>(field(ctx.fields, "ih_hcrc"));
    const uint32_t got = crc32_ieee(std::span<const uint8_t>(tmp.data(), tmp.size()));

    if (const char* a = arch_name(field(ctx.fields, "ih_arch"))) ctx.out.arch = a;
    if (const char* c = comp_name(field(ctx.fields, "ih_comp"))) ctx.out.compression = c;

    // Image name is a NUL-padded 32-byte string at offset 32.
    if (auto nm = r.bytes(off + 32, 32)) {
        std::string name(reinterpret_cast<const char*>(nm->data()), 32);
        name = name.substr(0, name.find('\0'));
        if (!name.empty()) ctx.out.label = name;  // the embedded uImage image name
    }

    if (got == want) {
        ctx.out.set_confidence(Confidence::Verified, "header CRC32 ok");
    } else {
        // Header CRC failed: this is not a validated uImage, so its ih_size field
        // (and the region size the signature derived from it) is untrusted. A
        // bogus ih_size that happens to fit in the file would otherwise let this
        // finding own — and skip-ahead past, masking — gigabytes of real data
        // behind it. Report the header but do not trust its size (mirrors the ELF
        // size guard). A genuine uImage has a valid header CRC.
        ctx.out.size = 0;
        ctx.out.set_confidence(Confidence::Structural, "header CRC32 mismatch (size not trusted)");
    }
    return true;
}

}  // namespace ft

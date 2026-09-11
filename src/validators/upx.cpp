// upx.cpp — UPX-packed-executable detection (see upx.hpp for the trailer layout).
#include "validators/upx.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ft {

namespace {

// UPX format ids are valid in [1, 46] and [129, 142], minus a handful that were
// reserved but never implemented. Mirrors Packer::isValidFormat (upx/packer_c.cpp).
bool is_valid_upx_format(int f) {
    if (!((f >= 1 && f <= 46) || (f >= 129 && f <= 142))) return false;
    switch (f) {
        case 6: case 11: case 13: case 17: case 38: case 41: case 130:
            return false;
        default:
            return true;
    }
}

// On-disk header size by version+format (upx/packhead.cpp getPackHeaderSize).
// 0 = unknown/too old to trust.
int packheader_size(int version, int format) {
    const bool dos_com = (format == 1 || format == 2);   // DOS_COM / DOS_SYS
    const bool dos_exe = (format == 3 || format == 7);   // DOS_EXE / DOS_EXEH
    int n;
    if (version <= 3) {
        n = 24;
    } else if (version <= 9) {
        n = dos_com ? 20 : dos_exe ? 25 : 28;
    } else {
        n = dos_com ? 22 : dos_exe ? 27 : 32;
    }
    return n < 20 ? 0 : n;
}

// Sum of header bytes [4 .. size-2] modulo 251 (upx get_packheader_checksum).
// Returns nullopt if any byte is out of range.
std::optional<uint8_t> header_checksum(const Reader& r, size_t off, int size) {
    unsigned c = 0;
    for (int i = 4; i < size - 1; ++i) {
        auto b = r.at<uint8_t>(off + static_cast<size_t>(i), Endian::Little);
        if (!b) return std::nullopt;
        c += *b;
    }
    return static_cast<uint8_t>(c % 251);
}

// First occurrence of `pat` in [start, end); npos if absent. Bounded, no alloc.
size_t find_bytes(const Reader& r, size_t start, size_t end, std::string_view pat) {
    if (pat.empty() || end > r.size() || start >= end || pat.size() > end - start)
        return std::string::npos;
    const size_t last = end - pat.size();
    for (size_t i = start; i <= last; ++i) {
        auto b = r.bytes(i, pat.size());
        if (b && std::equal(pat.begin(), pat.end(), b->begin())) return i;
    }
    return std::string::npos;
}

}  // namespace

std::optional<UpxHeader> parse_upx_packheader(const Reader& r, size_t off) {
    auto ver = r.at<uint8_t>(off + 4, Endian::Little);
    auto fmt = r.at<uint8_t>(off + 5, Endian::Little);
    auto meth = r.at<uint8_t>(off + 6, Endian::Little);
    auto lvl = r.at<uint8_t>(off + 7, Endian::Little);
    if (!ver || !fmt || !meth || !lvl) return std::nullopt;
    if (!is_valid_upx_format(*fmt)) return std::nullopt;

    const int size = packheader_size(*ver, *fmt);
    if (size == 0 || off + static_cast<size_t>(size) > r.size()) return std::nullopt;

    UpxHeader h;
    h.magic_off = off;
    h.header_size = size;
    h.version = *ver;
    h.format = *fmt;
    h.method = *meth;
    h.level = *lvl & 15;

    // Header checksum protects versions >= 10; require it there (this is what
    // rejects the loader's internal l_info "UPX!" and stray "UPX!" immediates).
    if (*ver >= 10) {
        auto want = r.at<uint8_t>(off + static_cast<size_t>(size) - 1, Endian::Little);
        auto got = header_checksum(r, off, size);
        if (!want || !got || *want != *got) return std::nullopt;
        h.checksum_ok = true;
    }

    const Endian e = (*fmt >= 128) ? Endian::Big : Endian::Little;
    if (*fmt >= 128) {
        auto u = r.at<uint32_t>(off + 8, e);
        auto c = r.at<uint32_t>(off + 12, e);
        auto fs = r.at<uint32_t>(off + 24, e);
        if (!u || !c) return std::nullopt;
        h.u_len = *u; h.c_len = *c; h.u_file_size = fs ? *fs : 0;
        auto flt = r.at<uint8_t>(off + 28, e); h.filter = flt ? *flt : 0;
    } else if (*fmt == 1 || *fmt == 2) {           // DOS COM/SYS: 16-bit sizes
        auto u = r.at<uint16_t>(off + 16, e);
        auto c = r.at<uint16_t>(off + 18, e);
        if (!u || !c) return std::nullopt;
        h.u_len = *u; h.c_len = *c; h.u_file_size = *u;
    } else {                                        // little-endian, 32-bit sizes
        auto u = r.at<uint32_t>(off + 16, e);
        auto c = r.at<uint32_t>(off + 20, e);
        auto fs = r.at<uint32_t>(off + 24, e);
        if (!u || !c) return std::nullopt;
        h.u_len = *u; h.c_len = *c; h.u_file_size = fs ? *fs : 0;
        auto flt = r.at<uint8_t>(off + 28, e); h.filter = flt ? *flt : 0;
    }

    // A real block has at least a couple of bytes each way (upx header check 4).
    if (h.c_len < 2 || h.u_len < 2) return std::nullopt;
    return h;
}

std::optional<UpxHeader> find_upx_packheader(const Reader& r, size_t start, size_t end) {
    end = std::min(end, r.size());
    size_t pos = start;
    while (pos < end) {
        size_t m = find_bytes(r, pos, end, "UPX!");
        if (m == std::string::npos) break;
        if (auto h = parse_upx_packheader(r, m)) return h;
        pos = m + 1;
    }
    return std::nullopt;
}

bool has_upx_ident(const Reader& r, size_t start, size_t end) {
    end = std::min(end, r.size());
    return find_bytes(r, start, end, "packed with the UPX") != std::string::npos ||
           find_bytes(r, start, end, "$Id: UPX ") != std::string::npos;
}

std::string upx_release_from_ident(const Reader& r, size_t start, size_t end) {
    end = std::min(end, r.size());
    size_t m = find_bytes(r, start, end, "$Id: UPX ");
    if (m == std::string::npos) return {};
    size_t p = m + 9;  // past "$Id: UPX "
    std::string ver;
    for (size_t i = p; i < end && ver.size() < 16; ++i) {
        auto b = r.at<uint8_t>(i, Endian::Little);
        if (!b) break;
        char ch = static_cast<char>(*b);
        if (ch == ' ' || ch == '\0') break;
        if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-' ||
            (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'))
            ver.push_back(ch);
        else
            break;
    }
    // "$Id: UPX (C) 1996-..." (the small ident) has no version token here.
    if (ver.empty() || ver[0] < '0' || ver[0] > '9') return {};
    return ver;
}

const char* upx_method_name(uint8_t m) {
    switch (m) {
        case 2: case 3: case 4: return "NRV2B";
        case 5: case 6: case 7: return "NRV2D";
        case 8: case 9: case 10: return "NRV2E";
        case 14: return "LZMA";
        case 15: return "deflate";
        default: return nullptr;
    }
}

void upx_format_desc(uint8_t f, std::string& family, std::string& arch) {
    struct Row { uint8_t f; const char* fam; const char* arch; };
    static const Row rows[] = {
        {9, "PE", "i386"},   {36, "PE", "amd64"},  {43, "PE", "arm64"},
        {44, "PE", "arm64"}, {21, "PE", "arm (WinCE)"},
        {10, "ELF", "i386"}, {12, "ELF", "i386"},  {19, "ELF", "i386"},
        {20, "ELF", "i386"}, {22, "ELF", "amd64"}, {23, "ELF", "arm"},
        {42, "ELF", "arm64"},{30, "ELF", "mipsel"},{137, "ELF", "mips"},
        {132, "ELF", "ppc32"},{133, "ELF", "armeb"},{39, "ELF", "ppc64le"},
        {140, "ELF", "ppc64"},{45, "ELF", "riscv64"},
        {29, "Mach-O", "i386"},{34, "Mach-O", "amd64"},{37, "Mach-O", "arm64"},
        {32, "Mach-O", "arm"},{131, "Mach-O", "ppc32"},{139, "Mach-O", "ppc64"},
        {134, "Mach-O", "fat"},{33, "Mach-O dylib", "i386"},{35, "Mach-O dylib", "amd64"},
        {138, "Mach-O dylib", "ppc32"},{142, "Mach-O dylib", "ppc64"},
        {15, "Linux vmlinuz", "i386"},{16, "Linux vmlinuz", "i386"},
        {27, "Linux vmlinux", "amd64"},{40, "Linux vmlinux", "ppc64le"},
        {1, "DOS", "com"},{2, "DOS", "sys"},{3, "DOS", "exe"},
    };
    for (const auto& row : rows) {
        if (row.f == f) { family = row.fam; arch = row.arch; return; }
    }
    family = "executable";
    arch = "format " + std::to_string(f);
}

bool validate_upx(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    auto h = parse_upx_packheader(r, ctx.offset);
    if (!h) return false;

    std::string family, arch;
    upx_format_desc(h->format, family, arch);
    const char* method = upx_method_name(h->method);

    ctx.out.size = static_cast<size_t>(h->header_size);
    ctx.out.endian = (h->format >= 128) ? Endian::Big : Endian::Little;
    ctx.out.label = "UPX-packed " + family;
    ctx.out.arch = arch;
    if (method) ctx.out.compression = method;

    // The trailer sits c_len bytes after the packed stream's start; the loader's
    // "$Id: UPX <ver>" banner is just ahead of it. Look back a bounded window.
    const size_t win = std::min<size_t>(ctx.offset, 16384);
    std::string rel = upx_release_from_ident(r, ctx.offset - win, ctx.offset);
    if (!rel.empty()) ctx.out.version = rel;

    std::string ev = "UPX PackHeader ";
    ev += h->checksum_ok ? "verified (checksum ok)" : "parsed";
    ev += "; " + (method ? std::string(method) : ("method " + std::to_string(h->method)));
    ev += " level " + std::to_string(h->level);
    ev += ", " + std::to_string(h->u_len) + " -> " + std::to_string(h->c_len) + " bytes";
    ev += "; stub format v" + std::to_string(h->version);

    ctx.out.set_confidence(h->checksum_ok ? Confidence::Verified : Confidence::Consistent, ev);
    return true;
}

}  // namespace ft

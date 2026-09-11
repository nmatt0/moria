// upx.hpp — UPX-packed-executable detection.
//
// UPX (the Ultimate Packer for eXecutables) compresses ELF/PE/Mach-O programs
// and appends a self-describing "PackHeader" trailer. The trailer is the most
// reliable marker: it always ends up in the file's overlay (past the ELF's
// declared program image), it carries the format/method/level/sizes, and since
// UPX version 10 it is protected by a checksum, so a match can be *verified*
// without decompressing anything.
//
// On-disk PackHeader (little-endian formats, the common ELF/PE/Mach case, 32 B):
//   +0  u8[4] magic "UPX!"       +16 le32 u_len   (uncompressed size)
//   +4  u8    version            +20 le32 c_len   (compressed size)
//   +5  u8    format             +24 le32 u_file_size
//   +6  u8    method             +28 u8   filter
//   +7  u8    level              +29 u8   filter_cto
//   +8  le32  u_adler            +30 u8   n_mru (0 or n-1)
//   +12 le32  c_adler            +31 u8   header_checksum = sum(bytes[4..30]) % 251
// Big-endian formats (format >= 128) reorder the 32-bit fields; see upx.cpp.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "reader.hpp"
#include "signature.hpp"

namespace ft {

// A parsed + validated UPX PackHeader trailer.
struct UpxHeader {
    size_t magic_off = 0;   // offset of the "UPX!" magic
    int header_size = 0;    // total on-disk header size (22/27/32 ...)
    uint8_t version = 0;
    uint8_t format = 0;
    uint8_t method = 0;
    uint8_t level = 0;
    uint8_t filter = 0;
    uint32_t u_len = 0;         // uncompressed (original) size
    uint32_t c_len = 0;         // compressed size == offset of the trailer from the packed-stream start
    uint32_t u_file_size = 0;   // original file size
    bool checksum_ok = false;   // header checksum verified (version >= 10)
};

// Parse and validate a PackHeader whose "UPX!" magic sits at `off`. Returns the
// header only when the format is a known UPX format and (for version >= 10) the
// checksum verifies; nullopt for the stub's internal l_info copy, an immediate
// in the decompressor code, or an unrelated "UPX!" byte sequence.
std::optional<UpxHeader> parse_upx_packheader(const Reader& r, size_t off);

// Scan [start, end) for the first "UPX!" that parses as a valid PackHeader.
std::optional<UpxHeader> find_upx_packheader(const Reader& r, size_t start, size_t end);

// True if the UPX loader ident string ("...packed with the UPX..." / "$Id: UPX ")
// occurs in [start, end). This survives magic tampering, so it is the tell for a
// UPX stub whose PackHeader magic was zeroed/altered.
bool has_upx_ident(const Reader& r, size_t start, size_t end);

// The UPX release parsed from the "$Id: UPX <version> " banner in [start, end),
// e.g. "4.24" or "5.2.0"; empty if the banner is absent.
std::string upx_release_from_ident(const Reader& r, size_t start, size_t end);

// Human name for a UPX compression method byte (NRV2B/NRV2D/NRV2E/LZMA/...).
const char* upx_method_name(uint8_t method);

// Family (e.g. "ELF", "PE", "Mach-O") and target arch (e.g. "amd64") for a UPX
// format byte. Unknown -> family "executable", arch "format <n>".
void upx_format_desc(uint8_t format, std::string& family, std::string& arch);

// Validator for signatures/upx.toml: interpret a "UPX!" match as a trailing
// PackHeader and, if it verifies, mark the finding as a UPX-packed executable
// (method, format, sizes) at the verified tier. Rejects non-trailer matches.
bool validate_upx(ValidatorCtx& ctx);

}  // namespace ft

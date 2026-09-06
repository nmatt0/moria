// cpio.cpp — cpio header validator.
// "newc" (070701) and "crc" (070702) use a 110-byte ASCII header of thirteen
// 8-hex-digit fields; "070707" (odc) is octal and only magic-validated here.
// For newc/crc we verify the hex fields and compute the entry's on-disk size:
//   align4(110 + c_namesize) + align4(c_filesize)
// so the scan skips to the next member and the coalesce pass merges the run.
#include "validators/cpio.hpp"

#include <optional>
#include <string>

namespace ft {

namespace {

// Parse `n` ASCII hex digits at file offset `at`. nullopt if any is non-hex.
std::optional<uint64_t> hex_at(const Reader& r, size_t at, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        auto b = r.bytes(at + i, 1);
        if (!b) return std::nullopt;
        uint8_t c = (*b)[0];
        uint64_t d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return std::nullopt;
        v = v * 16 + d;
    }
    return v;
}

uint64_t align4(uint64_t x) { return (x + 3) & ~uint64_t(3); }

}  // namespace

bool validate_cpio(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    auto magic = r.bytes(off, 6);
    if (!magic) return false;
    const bool newc = (std::string(reinterpret_cast<const char*>(magic->data()), 6) == "070701" ||
                       std::string(reinterpret_cast<const char*>(magic->data()), 6) == "070702");
    if (!newc) {
        // odc (070707): octal fields; accept on magic alone.
        ctx.out.set_confidence(Confidence::Magic, "cpio odc magic");
        return true;
    }

    // Thirteen 8-hex-digit fields follow the 6-byte magic (header = 110 bytes).
    const size_t FILESIZE = off + 6 + 6 * 8;
    const size_t NAMESIZE = off + 6 + 11 * 8;
    auto c_filesize = hex_at(r, FILESIZE, 8);
    auto c_namesize = hex_at(r, NAMESIZE, 8);
    // Verify the whole header is hex (fields we don't otherwise read).
    if (!hex_at(r, off + 6, 8) || !c_filesize || !c_namesize) return false;

    const uint64_t avail = r.size() - off;
    const uint64_t size = align4(110 + *c_namesize) + align4(*c_filesize);
    if (size == 0 || size > avail) {
        // Header parsed but size implausible; still a valid-looking entry.
        ctx.out.set_confidence(Confidence::Structural, "cpio newc header");
        return true;
    }
    ctx.out.size = size;
    ctx.out.set_confidence(Confidence::Consistent, "cpio newc entry, size computed");
    return true;
}

}  // namespace ft

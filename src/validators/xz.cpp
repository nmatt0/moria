// xz.cpp — xz stream-header validator.
//
// The signature matches the 6-byte magic (FD 37 7A 58 5A 00) and checks the two
// Stream Flags bytes (sf0 reserved == 0, sf1 high nibble reserved). That alone
// also matches any blob that merely starts with the magic and two plausible
// flag bytes - a string table compiled into a kernel ("\xfd""7zXZ\0" followed by
// the "XZ decompressor ..." messages) is a real-world case. The xz format
// (tukaani.org/xz/xz-file-format.txt, 2.1.1) puts a CRC32 of the Stream Flags
// right after them, which pins those false positives deterministically: this
// validator rejects the finding when that CRC32 does not match.
#include "validators/xz.hpp"

#include <cstdint>

#include "crc32.hpp"

namespace ft {

bool validate_xz(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    // Stream Header: magic[6] | Stream Flags[2] | CRC32(Stream Flags)[4, LE].
    auto flags = r.bytes(off + 6, 2);
    auto crc = r.at<uint32_t>(off + 8, Endian::Little);
    if (!flags || !crc) return false;  // header runs past EOF
    if (crc32_ieee(*flags) != *crc) return false;  // not an xz stream header

    ctx.out.set_confidence(Confidence::Verified, "xz stream-header CRC32 ok");
    return true;
}

}  // namespace ft

// vbf.cpp — VBF (Versatile Binary Format) firmware container validator.
//
// Layout:
//   ASCII   "vbf_version = X.Y;"  then  header { ... }
//   binary  block chain, repeated:
//             u32 be  start_address
//             u32 be  length
//             u8[len] data              # raw, or LZSS when dfi upper nibble != 0
//             u16 be  crc16             # CRC16-CCITT over the DECOMPRESSED data
// The block chain runs to EOF (no trailing file checksum in observed Ford PSCM
// images; the header carries file_checksum instead). Walking the chain yields
// the exact span. For uncompressed blocks the per-block CRC16 is verified here
// (cheap) -> verified; compressed containers top out at consistent since the
// CRC16 covers the decompressed payload (checked at extraction time).
#include "validators/vbf.hpp"

#include <string>

#include "crc16.hpp"
#include "vbf_header.hpp"

namespace ft {

namespace {
constexpr size_t kMaxBlocks = 4096;
}  // namespace

bool validate_vbf(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;

    // Reaffirm the magic (the signature matched "vbf_version" already).
    static constexpr uint8_t kMagic[] = {'v', 'b', 'f', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n'};
    if (!r.matches_at(base, kMagic)) return false;

    auto he = vbf::header_end(r, base);
    if (!he) return false;  // no well-formed `header { ... }` block
    const size_t hdr_end = *he;

    const uint8_t dfi = vbf::data_format(r, base, hdr_end);
    const bool compressed = vbf::is_compressed(dfi);

    // Walk the binary block chain.
    size_t off = hdr_end;
    size_t count = 0;
    bool crc_all_ok = true;
    bool crc_checked = false;
    while (count < kMaxBlocks) {
        auto start = r.at<uint32_t>(off, Endian::Big);
        auto len = r.at<uint32_t>(off + 4, Endian::Big);
        if (!start || !len) break;      // ran out of room for a block header
        if (*len == 0) break;           // zero-length block: not a real block
        const size_t data_off = off + 8;
        if (*len > r.size() - data_off) break;  // payload runs past EOF
        if (*len + 2 > r.size() - data_off) break;  // no room for the trailing crc16
        auto crc_stored = r.at<uint16_t>(data_off + *len, Endian::Big);
        if (!crc_stored) break;

        if (!compressed) {
            auto payload = r.bytes(data_off, *len);
            if (payload) {
                crc_checked = true;
                if (crc16_ccitt(*payload) != *crc_stored) crc_all_ok = false;
            }
        }
        off = data_off + *len + 2;
        ++count;
        if (off == r.size()) break;  // chain lands exactly on EOF
    }

    if (count == 0) {
        // Header parsed but no block chain: recognizably VBF, size unknown-ish.
        ctx.out.size = hdr_end - base;
        ctx.out.version = vbf::field(r, base, hdr_end, "vbf_version").value_or("");
        ctx.out.set_confidence(Confidence::Structural, "vbf header, no block chain");
        return true;
    }

    ctx.out.size = off - base;
    ctx.out.version = vbf::field(r, base, hdr_end, "vbf_version").value_or("");
    ctx.out.compression = compressed ? "lzss" : "none";
    if (auto part = vbf::field(r, base, hdr_end, "sw_part_number"); part && !part->empty())
        ctx.out.label = *part;

    const bool exact_eof = (off == r.size());
    if (!compressed && crc_checked && crc_all_ok) {
        ctx.out.set_confidence(Confidence::Verified,
                               "block chain parsed, per-block CRC16 verified");
    } else if (exact_eof) {
        ctx.out.set_confidence(Confidence::Consistent, "block chain spans file exactly");
    } else {
        ctx.out.set_confidence(Confidence::Consistent, "block chain parsed");
    }
    return true;
}

}  // namespace ft

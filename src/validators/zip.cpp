// zip.cpp — ZIP validator via the End-Of-Central-Directory record.
#include "validators/zip.hpp"

namespace ft {

bool validate_zip(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;
    const size_t filesz = r.size();
    static const std::vector<uint8_t> EOCD = {0x50, 0x4B, 0x05, 0x06};

    // EOCD sits within the last 64KiB (+22) of the archive; find the last one.
    size_t window = (filesz > 66000) ? filesz - 66000 : base;
    if (window < base) window = base;
    size_t eocd = 0;
    bool found = false;
    for (size_t i = window; i + 22 <= filesz; ++i) {
        if (r.matches_at(i, EOCD)) { eocd = i; found = true; }
    }
    if (!found) return true;  // keep structural default

    auto cd_size = r.at<uint32_t>(eocd + 12, Endian::Little);
    auto cd_offset = r.at<uint32_t>(eocd + 16, Endian::Little);
    auto comment_len = r.at<uint16_t>(eocd + 20, Endian::Little);
    if (!cd_size || !cd_offset || !comment_len) return true;

    // Central directory must end exactly at the EOCD, relative to the zip start.
    if (base + *cd_offset + *cd_size != eocd) return true;
    size_t eocd_end = eocd + 22 + *comment_len;
    if (eocd_end > filesz) return true;

    ctx.out.size = eocd_end - base;
    ctx.out.set_confidence(Confidence::Consistent, "EOCD found, archive size computed");
    return true;
}

}  // namespace ft

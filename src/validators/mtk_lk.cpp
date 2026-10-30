// mtk_lk.cpp — see mtk_lk.hpp. Header layout (u-boot tools/mtk_image.h, lk_hdr):
//   u32 magic@0 (0x58881688); u32 size@4 (payload after the header);
//   char name[32]@8; u32 loadaddr@40; u32 mode@44. 48 bytes, padded to 512.
#include "validators/mtk_lk.hpp"

#include <cstdint>
#include <optional>
#include <string>

#include "reader.hpp"

namespace ft {

bool validate_mtk_lk(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const uint64_t base = ctx.offset;

    // name[32] @8: the partition label ("lk"/"LK"), NUL- or 0xFF-terminated. A
    // real LK header carries a short printable-ASCII name; a coincidental 4-byte
    // magic over binary data does not. This is the false-positive gate.
    auto nb = r.bytes(static_cast<size_t>(base + 8), 32);
    if (!nb) return false;
    std::string name;
    for (uint8_t c : *nb) {
        if (c == 0x00 || c == 0xFF) break;
        if (c < 0x20 || c >= 0x7F) return false;  // non-printable -> not an LK header
        name.push_back(static_cast<char>(c));
    }
    if (name.empty()) return false;
    ctx.out.label = name;

    // size @4: payload bytes after the 512-byte header page. When header+payload
    // fits the available bytes the layout is internally consistent; otherwise
    // keep the structural (magic + valid name) tier rather than claim a span that
    // runs past EOF.
    auto sz = r.at<uint32_t>(base + 4, Endian::Little);
    if (!sz || *sz == 0) return true;
    constexpr uint64_t HDR = 512;  // 48-byte header padded to one page
    const uint64_t span = HDR + static_cast<uint64_t>(*sz);
    const uint64_t avail = r.size() > base ? r.size() - base : 0;
    if (span <= avail) {
        if (span > ctx.out.size) ctx.out.size = static_cast<size_t>(span);
        ctx.out.set_confidence(Confidence::Consistent, "LK header + payload fit in file");
    }
    return true;
}

}  // namespace ft

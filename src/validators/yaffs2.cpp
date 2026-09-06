// yaffs2.cpp — heuristic YAFFS2 detector (no magic in the format).
// The signature keys on the deprecated 0xFFFF "sum" at offset 8; this validator
// confirms the surrounding first-object header:
//   u32 type @0 (1=file 2=symlink 3=dir 4=hardlink 5=special)
//   u32 parent_object_id @4 (>= 1)
//   u16 0xFFFF @8 (already matched)
//   char name[] @10 (printable, or empty for the root)
// Little-endian only (the common case); big-endian YAFFS2 is not handled.
#include "validators/yaffs2.hpp"

namespace ft {

bool validate_yaffs2(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    auto name0 = r.bytes(off + 10, 1);
    if (!name0) return false;
    uint8_t c = (*name0)[0];
    if (!((c == 0) || (c >= 0x20 && c < 0x7F))) return false;  // printable/empty name

    // Try both byte orders for the object header (type @0, parent @4).
    for (Endian e : {Endian::Little, Endian::Big}) {
        auto type = r.at<uint32_t>(off + 0, e);
        auto parent = r.at<uint32_t>(off + 4, e);
        if (!type || !parent) continue;
        if (*type < 1 || *type > 5) continue;
        if (*parent < 1 || *parent > 0x0010'0000) continue;
        ctx.out.endian = e;
        ctx.out.set_confidence(Confidence::Structural, "yaffs2 first-object header heuristic");
        return true;
    }
    return false;
}

}  // namespace ft

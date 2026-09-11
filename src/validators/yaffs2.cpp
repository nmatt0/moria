// yaffs2.cpp — heuristic YAFFS2 detector (no magic in the format).
// The signature keys on the deprecated 0xFFFF "sum" at offset 8; this validator
// confirms the surrounding first-object header:
//   u32 type @0 (1=file 2=symlink 3=dir 4=hardlink 5=special)
//   u32 parent_object_id @4 (>= 1)
//   u16 0xFFFF @8 (already matched)
//   char name[] @10 (printable, or empty for the root)
//
// 0xFFFF is far too common to trust that header alone anywhere but the very
// start of a stream. At a nonzero offset (an embedded region inside a larger
// firmware blob) we additionally require a real NAND page/OOB geometry: the
// packed tag in chunk 0's spare area must describe chunk 0 as an object header
// (objectId >= 1, chunkId == 0). This is the same geometry probe the extractor
// uses, and it makes mid-stream detection precise instead of offset-0 only.
// Little-endian tags; the object-header u32 fields are tried both byte orders.
#include "validators/yaffs2.hpp"

#include <cstddef>
#include <utility>

namespace ft {

namespace {

// Confirm chunk 0's packed OOB tag for at least one standard NAND geometry:
// the tag sits at (page + tag_off) past the structure start and must name
// objectId >= 1 with chunkId == 0 (chunk 0 is the first object header). Mirrors
// detect_geometry() in extract/yaffs2.cpp.
bool nand_geometry_ok(const Reader& r, size_t base) {
    static const std::pair<size_t, size_t> GEOS[] = {
        {2048, 64}, {2048, 128}, {4096, 128}, {4096, 224}, {512, 16}, {2048, 32}, {8192, 256},
    };
    for (auto [page, spare] : GEOS) {
        for (size_t tag_off : {size_t(2), size_t(0)}) {
            if (tag_off + 16 > spare) continue;
            auto objid = r.at<uint32_t>(base + page + tag_off + 4, Endian::Little);
            auto chunkid = r.at<uint32_t>(base + page + tag_off + 8, Endian::Little);
            if (!objid || !chunkid) continue;
            if (*objid < 1 || *objid == 0xffffffff) continue;
            if (*chunkid != 0) continue;
            return true;
        }
    }
    return false;
}

}  // namespace

bool validate_yaffs2(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;  // structure start (magic_offset already subtracted)

    auto name0 = r.bytes(base + 10, 1);
    if (!name0) return false;
    uint8_t c = (*name0)[0];
    if (!((c == 0) || (c >= 0x20 && c < 0x7F))) return false;  // printable/empty name

    // Try both byte orders for the object header (type @0, parent @4).
    for (Endian e : {Endian::Little, Endian::Big}) {
        auto type = r.at<uint32_t>(base + 0, e);
        auto parent = r.at<uint32_t>(base + 4, e);
        if (!type || !parent) continue;
        if (*type < 1 || *type > 5) continue;
        if (*parent < 1 || *parent > 0x0010'0000) continue;

        // At offset 0 the stream's own identity is the yaffs2 candidate: the
        // header heuristic is enough (a standalone or minimal image). Mid-stream
        // demands a confirmed NAND geometry so a stray 0xFFFF cannot pass.
        if (base != 0 && !nand_geometry_ok(r, base)) return false;

        ctx.out.endian = e;
        ctx.out.set_confidence(
            Confidence::Structural,
            base == 0 ? "yaffs2 first-object header heuristic"
                      : "yaffs2 first-object header + NAND page/OOB geometry");
        return true;
    }
    return false;
}

}  // namespace ft

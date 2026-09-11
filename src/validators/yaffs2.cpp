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
// firmware blob) we additionally require a real NAND page/OOB geometry: chunk 0
// must be an object header whose packed spare tag names it (objectId >= 1,
// chunkId == 0), AND several following chunks must also parse under that same
// geometry — a single chunk's tag matches too many coincidental geometries to
// trust alone. Little-endian tags; object-header u32 fields are tried both orders.
//
// When a real OOB geometry is confirmed, the validator sizes the finding to the
// whole NAND image by walking its chunk stream to the last chunk that carries a
// valid tag, so one finding owns the region and the scanner masks its interior
// (as it does for squashfs/ext/ubi). A geometry cannot be confirmed for a
// data-only dump whose spare/OOB was stripped (no per-chunk tags exist): such an
// image is left as an unsized heuristic hit, the same limitation the extractor
// reports as `error:no-oob-geometry` — no tool can size or reconstruct it.
#include "validators/yaffs2.hpp"

#include <cstddef>
#include <utility>

namespace ft {

namespace {

// Standard MTD NAND geometries (page, spare), most common first. Mirrors the
// list in extract/yaffs2.cpp; keep the two in sync.
constexpr std::pair<size_t, size_t> GEOS[] = {
    {2048, 64}, {2048, 128}, {4096, 128}, {4096, 224}, {512, 16}, {2048, 32}, {8192, 256},
};

struct Geometry {
    size_t page = 0;
    size_t spare = 0;
    size_t stride = 0;
    size_t tag_off = 0;  // packed-tags offset within the OOB (2 on wide OOBs, 0 on tight)
};

enum class Chunk { Content, Erased, Broken };

// yaffs2 packs "extra header info" into an object-header chunk's tag: the
// chunkId field carries EXTRA_HEADER_INFO_FLAG (bit 31) with the parent object
// id in the low bits (and the object type in the top nibble of objectId), so a
// header chunk's stored chunkId is NOT literally 0. Real chunkId 0 (no extra
// info) is also a header. Data chunks carry their true (small) chunkId.
constexpr uint32_t YAFFS_EXTRA_HEADER_FLAG = 0x8000'0000u;
bool is_header_chunkid(uint32_t c) { return c == 0 || (c & YAFFS_EXTRA_HEADER_FLAG); }

// Classify chunk `i` of an image based at `base` under geometry `g`. The packed
// tag names objectId @(tag+4), chunkId @(tag+8), byteCount @(tag+12), where
// tag = chunk + page + tag_off.
Chunk classify(const Reader& r, size_t base, const Geometry& g, uint64_t i) {
    const uint64_t chunk = base + i * g.stride;
    const uint64_t tag = chunk + g.page + g.tag_off;
    auto objid = r.at<uint32_t>(tag + 4, Endian::Little);
    auto chunkid = r.at<uint32_t>(tag + 8, Endian::Little);
    auto bytecount = r.at<uint32_t>(tag + 12, Endian::Little);
    if (!objid || !chunkid || !bytecount) return Chunk::Broken;  // ran off the end
    if (*objid == 0 || *objid == 0xffffffff) return Chunk::Erased;  // unused / erased NAND
    if (is_header_chunkid(*chunkid)) {  // object header: its data area must be a real header
        auto type = r.at<uint32_t>(chunk + 0, Endian::Little);
        auto parent = r.at<uint32_t>(chunk + 4, Endian::Little);
        // parent 0 is valid: the root directory (object 1) and yaffs2's special
        // pseudo-dirs are parented to 0. Only the type range is required here;
        // the extra-header cross-check below binds parent when it is encoded.
        if (!type || *type < 1 || *type > 5 || *parent > 0x0010'0000) return Chunk::Broken;
        // Extra-header encoding cross-check: the parent packed into the tag's
        // chunkId (low bits, flags masked off) must equal the object header's own
        // parent field. This is a strong yaffs2 signal that arbitrary structured
        // data won't satisfy, so a confirmed extra-header chunk counts for a lot.
        if ((*chunkid & YAFFS_EXTRA_HEADER_FLAG) && (*chunkid & 0x0fff'ffffu) != *parent)
            return Chunk::Broken;
        return Chunk::Content;
    }
    // data chunk: byteCount fits a page, chunkId is plausible
    if (*bytecount <= g.page && *chunkid <= 0x0010'0000) return Chunk::Content;
    return Chunk::Broken;
}

// Find a geometry under which chunk 0 is an object header AND the first several
// chunks all parse (content or erased, never broken). Requiring a run rejects
// the coincidental single-chunk matches that any geometry can produce over
// arbitrary data. Returns false for a data-only dump with no real OOB tags.
bool detect_geometry(const Reader& r, size_t base, Geometry& out) {
    constexpr uint64_t MIN_RUN = 32;     // chunks that must parse under the geometry
    constexpr uint64_t MIN_CONTENT = 3;  // of which this many must be real records
    // (each content chunk is strongly validated - an extra-header chunk is
    // parent-cross-checked - so a low floor stays safe while admitting sparse
    // images: a few files written into a large, mostly-erased flash volume.)
    for (auto [page, spare] : GEOS) {
        for (size_t tag_off : {size_t(2), size_t(0)}) {
            if (tag_off + 16 > spare) continue;
            Geometry g{page, spare, page + spare, tag_off};
            // chunk 0 must be an object header (chunkId 0, possibly extra-header
            // encoded) naming a real object.
            auto objid = r.at<uint32_t>(base + page + tag_off + 4, Endian::Little);
            auto chunkid = r.at<uint32_t>(base + page + tag_off + 8, Endian::Little);
            if (!objid || !chunkid || *objid == 0xffffffff || !is_header_chunkid(*chunkid)) continue;
            if (classify(r, base, g, 0) != Chunk::Content) continue;
            const uint64_t navail = (r.size() - base) / g.stride;
            const uint64_t need = navail < MIN_RUN ? navail : MIN_RUN;
            bool ok = true;
            uint64_t content = 0;
            for (uint64_t i = 0; i < need; ++i) {
                Chunk k = classify(r, base, g, i);
                if (k == Chunk::Broken) { ok = false; break; }
                if (k == Chunk::Content) ++content;
            }
            // Require enough real records in the run (scaled down for a tiny
            // image). A data-only dump with no OOB never sustains this under a
            // single geometry; a coincidental all-erased run is rejected too.
            const uint64_t min_content = need < MIN_CONTENT ? need : MIN_CONTENT;
            if (ok && content >= min_content) { out = g; return true; }
        }
    }
    return false;
}

// A named page-aligned yaffs2 object header (chunkId 0): type 1..5, parent
// 1..1M, the deprecated 0xFFFF sum @8, and a plausible FILENAME @10 — a non-
// space printable first byte, then printable bytes up to a NUL. The filename
// requirement is what separates a real object from structured non-yaffs2 data
// that merely has type/parent/0xFFFF-shaped bytes at a page boundary (those
// runs are typically empty- or binary-named). The single nameless object in a
// real image is the root dir, which is the anchor, not a confirming header.
bool is_object_header(const Reader& r, uint64_t off, Endian e) {
    auto type = r.at<uint32_t>(off + 0, e);
    auto parent = r.at<uint32_t>(off + 4, e);
    auto sum = r.at<uint16_t>(off + 8, Endian::Little);
    auto nm = r.bytes(off + 10, 4);
    if (!type || !parent || !sum || !nm) return false;
    if (*type < 1 || *type > 5 || *parent < 1 || *parent > 0x0010'0000) return false;
    if (*sum != 0xffff) return false;
    uint8_t c0 = (*nm)[0];
    if (c0 < 0x21 || c0 > 0x7e) return false;  // a real filename starts with a visible char
    for (size_t i = 1; i < 4; ++i) {
        uint8_t c = (*nm)[i];
        if (c == 0) break;                       // NUL-terminated: fine
        if (c < 0x20 || c > 0x7e) return false;  // otherwise must stay printable
    }
    return true;
}

// A data-only (OOB-stripped) dump has no per-chunk tags, so it cannot be sized
// by the chunk walk. Its object headers survive at page boundaries, though.
// Scan them to bound the region heuristically: the extent runs to the last
// header found, bridging the data pages between headers up to a budget. Returns
// {extent, header_count}; extent is 0 when no page size fits.
struct DataOnly {
    uint64_t extent = 0;
    uint32_t headers = 0;
};
DataOnly data_only_scan(const Reader& r, size_t base, Endian e) {
    constexpr uint64_t GAP_BUDGET = 16u << 20;  // data pages tolerated between headers
    static const size_t PAGES[] = {2048, 4096, 512};
    DataOnly best;
    for (size_t page : PAGES) {
        uint32_t headers = 0;
        uint64_t last = base;
        for (uint64_t off = base; off + 16 <= r.size(); off += page) {
            if (is_object_header(r, off, e)) {
                ++headers;
                last = off;
            } else if (off - last > GAP_BUDGET) {
                break;  // left the header run (trailing data / next region)
            }
        }
        if (headers > best.headers) best = {(last - base) + page, headers};
    }
    return best;
}

// Walk the chunk stream and return the image size: (index of the last
// content-bearing chunk + 1) * stride. Erased chunks are tolerated inside the
// image; a broken chunk, a long trailing erased run, EOF, or a hard cap ends it.
uint64_t image_size(const Reader& r, size_t base, const Geometry& g) {
    constexpr uint64_t MAX_CHUNKS = 20'000'000;  // matches the extractor cap
    constexpr uint64_t GAP_LIMIT = 2048;         // consecutive erased chunks tolerated
    const uint64_t nchunks = (r.size() - base) / g.stride;
    uint64_t last_content = 0, gap = 0;
    bool any = false;
    for (uint64_t i = 0; i < nchunks && i <= MAX_CHUNKS; ++i) {
        switch (classify(r, base, g, i)) {
            case Chunk::Content: last_content = i; any = true; gap = 0; break;
            case Chunk::Erased:  if (any && ++gap > GAP_LIMIT) return (last_content + 1) * g.stride;
                                 break;
            case Chunk::Broken:  return (last_content + 1) * g.stride;
        }
    }
    return (last_content + 1) * g.stride;
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

        ctx.out.endian = e;

        // A confirmed multi-chunk OOB geometry both (a) lets a mid-stream hit be
        // trusted (a stray 0xFFFF cannot fake a run of valid chunks) and (b)
        // yields the image size. The image is sizable and extractable: no caveat.
        Geometry g;
        if (detect_geometry(r, base, g)) {
            uint64_t sz = image_size(r, base, g);
            if (sz > r.size() - base) sz = r.size() - base;
            ctx.out.size = sz;  // owns the region; interior is masked
            ctx.out.set_confidence(Confidence::Structural,
                                   "yaffs2 first-object header + NAND page/OOB geometry");
            return true;
        }

        // No OOB. A data-only dump has no per-chunk tags, so it cannot be sized
        // or extracted by any tool. Require a run of object headers before
        // trusting a mid-stream hit (one stray 0xFFFF is not a filesystem), then
        // size to the header span and attach the actionable diagnostic. At
        // offset 0 the stream's own identity is the candidate, so a lone header
        // still stands (a minimal image) — but with the same no-OOB caveat.
        // Three page-aligned object headers (each type/parent/name-validated) is
        // effectively impossible by chance, so it is a safe mid-stream floor.
        constexpr uint32_t MIN_HEADERS = 3;
        DataOnly d = data_only_scan(r, base, e);
        if (base != 0 && d.headers < MIN_HEADERS) return false;

        if (d.headers >= MIN_HEADERS && d.extent > 0) {
            uint64_t sz = d.extent;
            if (sz > r.size() - base) sz = r.size() - base;
            ctx.out.size = sz;  // owns the header span so the interior is masked
        }
        // A confirmed run of object headers is a real yaffs2 region (structural),
        // even though it is not reconstructable — that caveat is the diagnostic's
        // job, not the tier's. Owning the region collapses the per-header hits
        // into this one finding.
        ctx.out.set_confidence(Confidence::Structural,
                               "yaffs2 object headers, no OOB/spare (data-only dump)");
        ctx.out.diagnostics.push_back(
            {"warning", "yaffs2-no-oob",
             "YAFFS2 object headers present but no usable per-chunk OOB/spare tags were found "
             "(stripped, or an unrecognized tag layout); the image cannot be sized precisely "
             "or extracted."});
        return true;
    }
    return false;
}

}  // namespace ft

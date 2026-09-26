// otra.cpp — Artosyn OTRA firmware image validator. See src/otra.hpp for layout.
//
// Header + constraints already matched (magic 'OTRA', ver/hashsize/siglen sane).
// Here we: (1) confirm body_size == filesize-0x220, (2) recompute SHA-256 over the
// body and compare to the stored digest (a match is the firmware's own integrity
// gate -> Verified tier), and (3) classify the body as segmented (populated
// partition/segment tables + contiguous LZO payload chain; partitions surface as
// members) or flat (a raw dual-slot flash image).
#include "validators/otra.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>

#include "deobfuscate/cipher.hpp"
#include "otra_format.hpp"

namespace ft {

namespace {
std::string hex(uint64_t v) {
    char buf[19];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}
}  // namespace

bool validate_otra(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;

    auto ho = otra::parse_otra(r, base);
    if (!ho) return false;
    const otra::Header& h = *ho;

    // The container runs from the header to EOF (body_size counts from 0x220).
    if (base + otra::kHeaderEnd > r.size()) return false;
    const size_t avail_body = r.size() - (base + otra::kHeaderEnd);
    if (h.body_size != avail_body) return false;  // trailing junk / truncated -> not a clean OTRA

    ctx.out.size = r.size() - base;
    if (!h.version.empty()) ctx.out.version = h.version;

    auto tables = otra::parse_otra_tables(r, base, h);
    ctx.out.compression = tables.segmented ? "lzo1x" : "none";

    if (tables.segmented) {
        for (const auto& p : tables.parts) {
            auto sel = otra::segments_of(p, tables.segs);
            if (sel.empty()) continue;  // inactive slot / no payload in this image
            Member m;
            m.name = p.name.empty() ? "part" : p.name;
            m.offset = static_cast<size_t>(sel.front()->file_off);
            uint64_t comp = 0, decomp = 0;
            for (const auto* s : sel) { comp += s->data_len; decomp += s->flash_len; }
            m.size = static_cast<size_t>(comp);  // compressed span in the file
            m.note = std::to_string(sel.size()) + (sel.size() == 1 ? " seg -> " : " segs -> ") +
                     hex(decomp) + ((p.flags & 1u) ? " · active" : "");
            ctx.out.members.push_back(std::move(m));
        }
    }

    // SHA-256 over the body is the firmware's own integrity check; recompute it.
    auto body = r.bytes(base + otra::kHeaderEnd, avail_body);
    auto stored = r.bytes(base + otra::kHashOff, otra::kHashLen);
    bool sha_ok = false;
    if (body && stored && h.hashsize == otra::kHashLen) {
        auto calc = sha256(*body);
        sha_ok = stored->size() == calc.size() &&
                 std::equal(calc.begin(), calc.end(), stored->begin());
    }

    if (sha_ok)
        ctx.out.set_confidence(Confidence::Verified, "SHA-256(body) matches stored digest");
    else if (tables.segmented && tables.chain_spans_body)
        ctx.out.set_confidence(Confidence::Consistent, "segment payload chain spans the body");
    else
        ctx.out.set_confidence(Confidence::Structural, "OTRA header consistent");
    return true;
}

}  // namespace ft

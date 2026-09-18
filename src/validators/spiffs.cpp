// spiffs.cpp — SPIFFS identification validator. See spiffs.hpp.
#include "validators/spiffs.hpp"

#include <string>

#include "spiffs_parse.hpp"

namespace ft {

bool validate_spiffs(ValidatorCtx& ctx) {
    // The anchor (an object-index header) can sit anywhere in the SPIFFS image;
    // geometry is inferred over the whole reader from offset 0, so this handles a
    // standalone SPIFFS partition (the common case: a dumped partition, or a
    // partition moria extracted and re-scanned).
    // SPIFFS is an MCU SPI-NOR filesystem (MB-scale); cap the inference so a stray
    // anchor in a large non-SPIFFS image can't drive a full-image multi-geometry
    // scan.
    if (ctx.reader.size() > (64u << 20)) return false;
    SpiffsGeom g = spiffs_infer(ctx.reader);
    if (!g.ok || g.complete == 0) return false;  // need >=1 fully-recovered file

    Finding& out = ctx.out;
    out.type = "spiffs";
    out.category = "filesystem";
    out.endian = Endian::Little;
    out.offset = 0;                 // the SPIFFS region starts at the image origin
    out.size = ctx.reader.size();   // spans the whole image so interior isn't re-scanned
    std::string geom = "page " + std::to_string(g.page_size) + "/block " + std::to_string(g.block_size);
    out.label = geom;  // rendered in quotes in NOTES
    out.set_confidence(Confidence::Consistent,
                       "SPIFFS: " + std::to_string(g.files) + " file(s), inferred " + geom);
    return true;
}

}  // namespace ft

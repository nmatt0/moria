// dtb.cpp — FDT/DTB refinement validator.
//
// A plain device-tree blob and a U-Boot FIT (Flattened Image Tree) share the
// FDT magic (0xd00dfeed). A FIT is an FDT whose root node contains an `/images`
// subnode holding the packed subimages. When we see that structure, reclassify
// the match as `fit` (category container) so the FIT extractor is dispatched;
// otherwise the match stays a `dtb` (a hardware description with nothing to
// unpack). The dtb signature's constraints already verified the header offsets,
// so this only adds the FIT distinction.
#include "validators/dtb.hpp"

#include "extract/fit.hpp"

namespace ft {

bool validate_dtb(ValidatorCtx& ctx) {
    uint64_t span = 0;
    if (fdt_is_fit(ctx.reader, ctx.offset, &span)) {
        ctx.out.type = "fit";
        ctx.out.category = "container";
        ctx.out.set_confidence(Confidence::Consistent, "FIT: root /images node present");
        // Claim the appended external-data payloads too (the FDT totalsize covers
        // only the tree), so inner subimages aren't reported as separate findings.
        if (span > ctx.out.size && ctx.offset + span <= ctx.reader.size()) ctx.out.size = span;
    }
    return true;  // a plain DTB is still a valid match
}

}  // namespace ft

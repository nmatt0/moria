// deobf.cpp — see deobf.hpp.
#include "validators/deobf.hpp"

#include "deobfuscate/scheme.hpp"

namespace ft {

bool validate_deobf(ValidatorCtx& ctx) {
    auto p = probe_scheme(ctx.reader, ctx.offset);
    if (!p) return false;  // bare magic, no valid header structure -> drop the finding
    if (p->total_span > ctx.out.size) ctx.out.size = p->total_span;
    if (p->validated)
        ctx.out.set_confidence(Confidence::Verified,
                               "encrypted; decryptable (" + p->cipher + ") - -e to recover");
    else
        ctx.out.set_confidence(Confidence::Structural, "encrypted; no working key");
    return true;
}

}  // namespace ft

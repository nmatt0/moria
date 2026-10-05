// cfbf.cpp — compound file (CFBF) validator. See the header.
#include "validators/cfbf.hpp"

#include <cstdio>

#include "cfbf_parse.hpp"

namespace ft {

bool validate_cfbf(ValidatorCtx& ctx) {
    Cfbf c;
    if (!cfbf_parse(ctx.reader, ctx.offset, c)) return false;
    if (c.streams == 0) return false;  // a compound file with no stream is noise

    ctx.out.size = static_cast<size_t>(c.span);

    char ver[16];
    std::snprintf(ver, sizeof(ver), "%u.%u", c.ver_major, c.ver_minor);
    ctx.out.version = ver;

    char label[96];
    std::snprintf(label, sizeof(label), "%s%zu storages, %zu streams",
                  c.msi ? "msi, " : "", c.storages, c.streams);
    ctx.out.label = label;

    const uint64_t avail = ctx.reader.size() - ctx.offset;
    if (c.span <= avail)
        ctx.out.set_confidence(Confidence::Verified, "FAT + directory parse, span within EOF");
    else
        ctx.out.set_confidence(Confidence::Consistent, "FAT + directory parse");
    return true;
}

}  // namespace ft

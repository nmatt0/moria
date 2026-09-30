// cab.cpp — Microsoft Cabinet validator. See the header.
#include "validators/cab.hpp"

#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include "cab_parse.hpp"

namespace ft {

bool validate_cab(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;

    CabHeader h;
    if (!cab_header(r, base, h)) return false;

    std::vector<CabFolder> folders;
    if (!cab_folders(r, base, h, folders) || folders.empty()) return false;
    std::vector<CabFile> files;
    if (!cab_files(r, base, h, files) || files.empty()) return false;

    const size_t avail = r.size() - base;
    if (h.cb_cabinet == 0 || h.cb_cabinet > avail + 0x1000) return false;
    ctx.out.size = h.cb_cabinet <= avail ? h.cb_cabinet : avail;

    // Name the codec(s) in use. A cabinet may mix them per folder, though in
    // practice one tool writes the whole set the same way.
    std::set<std::string> codecs;
    for (const CabFolder& f : folders) codecs.insert(cab_comp_name(f.comp()));
    std::string comp;
    for (const std::string& c : codecs) comp += (comp.empty() ? "" : "+") + c;
    ctx.out.compression = comp;

    char ver[16];
    std::snprintf(ver, sizeof(ver), "%u.%u", h.ver_major, h.ver_minor);
    ctx.out.version = ver;

    char label[80];
    std::snprintf(label, sizeof(label), "%u folders, %u files", h.nfolders, h.nfiles);
    ctx.out.label = label;

    if (h.flags & (kCabPrevCabinet | kCabNextCabinet))
        ctx.out.diagnostics.push_back({"warning", "cab-spanned",
                                       "part of a multi-cabinet set; files continued from or into "
                                       "another cabinet cannot be completed from this file alone"});

    if (h.cb_cabinet == avail)
        ctx.out.set_confidence(Confidence::Verified, "folder + file tables parse, cbCabinet == EOF");
    else
        ctx.out.set_confidence(Confidence::Consistent, "folder + file tables parse");
    return true;
}

}  // namespace ft

// wince_rom.cpp — Windows CE XIP ROM validator. See the header.
//
// "ECEC" at offset 0x40 is only four bytes and is copied verbatim into images
// that are not ROMs at all (the Crestron eboot carries it with a pTOC pointing
// tens of megabytes past its own end). The real evidence is that pTOC resolves
// to a ROMHDR whose first field is the image's own virtual base and whose
// module + file tables fit inside the file; that resolution is what separates a
// ROM from a stray signature, so it decides the tier here.
#include "validators/wince_rom.hpp"

#include <cstdio>

#include "wince_rom_parse.hpp"

namespace ft {

bool validate_wince_rom(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;

    CeRomHeader h;
    if (!ce_rom_header(r, base, h)) {
        // No ROM behind the signature. At the start of a file that is worth
        // saying (a bootloader built from the same sources carries the header
        // verbatim); four bytes deep inside some other image it is just noise,
        // so drop it rather than report a container that isn't there.
        if (base != 0) return false;
        ctx.out.size = 0;
        ctx.out.set_confidence(Confidence::Magic,
                               "ECEC signature; pTOC does not resolve to a ROMHDR");
        return true;
    }

    const size_t avail = r.size() - base;
    const uint64_t span = h.span();
    ctx.out.size = static_cast<size_t>(span <= avail ? span : avail);

    if (const char* a = ce_cpu_arch(h.cpu); *a) ctx.out.arch = a;

    // Any file stored shorter than its real size is CECompress-coded; the same
    // codec covers compressed module sections.
    std::vector<CeFile> files;
    bool compressed = false;
    if (ce_rom_files(r, base, h, files))
        for (const CeFile& f : files)
            if (f.comp != f.real) {
                compressed = true;
                break;
            }
    ctx.out.compression = compressed ? "cecompress" : "none";

    char ev[160];
    std::snprintf(ev, sizeof(ev), "ROMHDR at 0x%zx: base 0x%08x, %u modules, %u files", h.hdr_off,
                  h.physfirst, h.nummods, h.numfiles);
    // The tables resolving inside the image is a decode-grade check: a stray
    // signature cannot produce a self-consistent TOC. Short of the full span
    // being present, keep it one tier lower.
    ctx.out.set_confidence(span <= avail ? Confidence::Verified : Confidence::Consistent, ev);

    char label[64];
    std::snprintf(label, sizeof(label), "%u modules, %u files", h.nummods, h.numfiles);
    ctx.out.label = label;
    return true;
}

}  // namespace ft

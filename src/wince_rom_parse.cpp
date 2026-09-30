// wince_rom_parse.cpp — ROMHDR location and table walking. See the header.
#include "wince_rom_parse.hpp"

#include <algorithm>

namespace ft {

namespace {

constexpr size_t kSigOff = 0x40;      // "ECEC" + pTOC live here
constexpr size_t kRomHdrSize = 0x4c;  // ROMHDR, followed by the two tables
constexpr size_t kTocEntry = 32;      // TOCentry
constexpr size_t kFilesEntry = 28;    // FILESentry
constexpr uint32_t kMaxModules = 4096;
constexpr uint32_t kMaxFiles = 8192;
constexpr size_t kMaxName = 260;

// Virtual bases romimage has used for CE 4/5/6 kernel regions. Tried when the
// image does not carry a usable TOC-offset hint.
constexpr uint32_t kKnownBases[] = {0x80000000, 0x80200000, 0x80100000, 0x84000000,
                                    0x88000000, 0x8c000000, 0x00000000};

// pTOC does not always point exactly at the ROMHDR: some images place it a few
// bytes short (CE 6 images observed here put the header at pTOC + 8), so a
// candidate offset is probed across a small aligned skew.
constexpr size_t kMaxSkew = 0x40;

// Does a ROMHDR at file offset `off` describe an image based at `vbase` that
// fits the file? This is the whole acceptance test for a TOC candidate.
bool hdr_plausible(const Reader& r, size_t base, size_t off, uint32_t vbase) {
    if (off < base || off - base > r.size() - base) return false;
    if (r.size() - off < kRomHdrSize) return false;
    auto pf = r.at<uint32_t>(off, Endian::Little);
    auto pl = r.at<uint32_t>(off + 4, Endian::Little);
    auto nm = r.at<uint32_t>(off + 8, Endian::Little);
    auto nf = r.at<uint32_t>(off + 0x28, Endian::Little);
    if (!pf || !pl || !nm || !nf) return false;
    if (*pf != vbase || *pf >= *pl) return false;
    if (*nm == 0 || *nm > kMaxModules || *nf > kMaxFiles) return false;
    // The image span must roughly match the file; a ROM is sometimes stored with
    // its tail trimmed, so allow a little slack rather than demanding equality.
    const uint64_t span = uint64_t(*pl) - *pf;
    if (span > uint64_t(r.size() - base) + 0x10000) return false;
    // Both tables have to be inside the file.
    const uint64_t tables = uint64_t(kRomHdrSize) + uint64_t(*nm) * kTocEntry +
                            uint64_t(*nf) * kFilesEntry;
    if (tables > r.size() - off) return false;
    return true;
}

bool load_hdr(const Reader& r, size_t off, CeRomHeader& h) {
    auto u32 = [&](size_t o) { return r.at<uint32_t>(off + o, Endian::Little).value_or(0); };
    h.hdr_off = off;
    h.physfirst = u32(0x00);
    h.physlast = u32(0x04);
    h.nummods = u32(0x08);
    h.ramstart = u32(0x0c);
    h.ramfree = u32(0x10);
    h.ramend = u32(0x14);
    h.numfiles = u32(0x28);
    h.kflags = u32(0x2c);
    h.fsram = u32(0x30);
    h.cpu = r.at<uint16_t>(off + 0x3c, Endian::Little).value_or(0);
    h.misc = r.at<uint16_t>(off + 0x3e, Endian::Little).value_or(0);
    return true;
}

std::string read_cstr(const Reader& r, size_t off) {
    std::string s;
    for (size_t i = 0; i < kMaxName; ++i) {
        auto c = r.at<uint8_t>(off + i, Endian::Little);
        if (!c || *c == 0) break;
        s += static_cast<char>(*c);
    }
    return s;
}

}  // namespace

bool ce_rom_header(const Reader& r, size_t base, CeRomHeader& out) {
    if (base > r.size() || r.size() - base < kSigOff + 8) return false;
    auto ptoc = r.at<uint32_t>(base + kSigOff + 4, Endian::Little);
    if (!ptoc || *ptoc == 0) return false;
    out.ptoc = *ptoc;

    // Candidate 1: the TOC offset romimage stores next to pTOC. When present it
    // gives the virtual base directly (physfirst == pTOC - toc_offset).
    auto toc_off = r.at<uint32_t>(base + kSigOff + 8, Endian::Little);
    if (toc_off && *toc_off != 0 && *toc_off <= *ptoc) {
        const uint32_t vbase = *ptoc - *toc_off;
        for (size_t skew = 0; skew < kMaxSkew; skew += 4) {
            const size_t off = base + size_t(*toc_off) + skew;
            if (hdr_plausible(r, base, off, vbase)) return load_hdr(r, off, out);
        }
    }

    // Candidate 2: the virtual bases romimage conventionally uses.
    for (uint32_t vbase : kKnownBases) {
        if (*ptoc < vbase) continue;
        const uint64_t rel = uint64_t(*ptoc) - vbase;
        if (rel > r.size() - base) continue;
        for (size_t skew = 0; skew < kMaxSkew; skew += 4) {
            const size_t off = base + size_t(rel) + skew;
            if (hdr_plausible(r, base, off, vbase)) return load_hdr(r, off, out);
        }
    }

    // Candidate 3: an unconventional base. The ROMHDR's first field IS the
    // virtual base, and its file offset is pTOC - base + skew, so a header at
    // offset `o` must satisfy u32[o] == pTOC - (o - base) + skew. One aligned
    // pass over the image finds it without guessing the base.
    //
    // Only for a ROM that is the whole file. "ECEC" is four bytes, so a large
    // image can carry many stray matches, and running a full pass for each
    // would be quadratic; every image romimage actually produces is resolved by
    // one of the two cheap candidates above.
    if (base != 0) return false;
    const size_t end = r.size() >= kRomHdrSize ? r.size() - kRomHdrSize : 0;
    for (size_t o = (base + 3) & ~size_t(3); o + 4 <= end; o += 4) {
        auto v = r.at<uint32_t>(o, Endian::Little);
        if (!v) break;
        const uint64_t rel = o - base;
        // skew = v + rel - pTOC, valid only in [0, kMaxSkew) and 4-aligned.
        const uint64_t skew = uint64_t(*v) + rel - *ptoc;
        if (skew >= kMaxSkew || (skew & 3) != 0) continue;
        if (hdr_plausible(r, base, o, *v)) return load_hdr(r, o, out);
    }
    return false;
}

size_t ce_rom_offset(const Reader& r, size_t base, const CeRomHeader& h, uint32_t addr,
                     size_t need) {
    if (addr < h.physfirst) return SIZE_MAX;
    const uint64_t rel = uint64_t(addr) - h.physfirst;
    const uint64_t off = uint64_t(base) + rel;
    if (off > r.size() || need > r.size() - off) return SIZE_MAX;
    return static_cast<size_t>(off);
}

bool ce_rom_modules(const Reader& r, size_t base, const CeRomHeader& h,
                    std::vector<CeModule>& out) {
    const size_t table = h.hdr_off + kRomHdrSize;
    if (!r.bytes(table, size_t(h.nummods) * kTocEntry)) return false;
    out.reserve(h.nummods);
    for (uint32_t i = 0; i < h.nummods; ++i) {
        const size_t e = table + size_t(i) * kTocEntry;
        auto u32 = [&](size_t o) { return r.at<uint32_t>(e + o, Endian::Little).value_or(0); };
        CeModule m;
        m.attr = u32(0x00);
        m.size = u32(0x0c);
        const uint32_t name_ptr = u32(0x10);
        m.e32 = u32(0x14);
        m.o32 = u32(0x18);
        m.load = u32(0x1c);
        const size_t no = ce_rom_offset(r, base, h, name_ptr, 1);
        if (no == SIZE_MAX) continue;
        m.name = read_cstr(r, no);
        if (m.name.empty()) continue;
        out.push_back(std::move(m));
    }
    return true;
}

bool ce_rom_files(const Reader& r, size_t base, const CeRomHeader& h, std::vector<CeFile>& out) {
    const size_t table = h.hdr_off + kRomHdrSize + size_t(h.nummods) * kTocEntry;
    if (!r.bytes(table, size_t(h.numfiles) * kFilesEntry)) return false;
    out.reserve(h.numfiles);
    for (uint32_t i = 0; i < h.numfiles; ++i) {
        const size_t e = table + size_t(i) * kFilesEntry;
        auto u32 = [&](size_t o) { return r.at<uint32_t>(e + o, Endian::Little).value_or(0); };
        CeFile f;
        f.attr = u32(0x00);
        f.real = u32(0x0c);
        f.comp = u32(0x10);
        const uint32_t name_ptr = u32(0x14);
        f.load = u32(0x18);
        const size_t no = ce_rom_offset(r, base, h, name_ptr, 1);
        if (no == SIZE_MAX) continue;
        f.name = read_cstr(r, no);
        if (f.name.empty()) continue;
        out.push_back(std::move(f));
    }
    return true;
}

const char* ce_cpu_arch(uint16_t cpu) {
    switch (cpu) {
        case 0x014c: return "x86";
        case 0x0162:
        case 0x0166:
        case 0x0168:
        case 0x0169: return "mips";
        case 0x01a2:
        case 0x01a3:
        case 0x01a4:
        case 0x01a6:
        case 0x01a8: return "sh";
        case 0x01c0:
        case 0x01c2:
        case 0x01c4: return "arm";
        case 0x0200: return "ia64";
        case 0x8664: return "x86_64";
        default: return "";
    }
}

}  // namespace ft

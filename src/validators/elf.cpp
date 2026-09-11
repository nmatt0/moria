// elf.cpp — ELF header refinement validator.
// e_ident is parsed by the layout; EI_DATA (byte 5) selects the endianness for
// the multi-byte e_type (offset 16) and e_machine (offset 18).
#include "validators/elf.hpp"

#include <algorithm>
#include <string>

#include "validators/upx.hpp"

namespace ft {

void detect_upx_tamper(ValidatorCtx& ctx, Endian e, bool is64);

namespace {
uint64_t field(const FieldMap& f, const char* k) {
    auto it = f.find(k);
    return it == f.end() ? 0 : it->second;
}

const char* machine_name(uint16_t m) {
    switch (m) {
        case 2: return "sparc";
        case 3: return "x86";
        case 8: return "mips";
        case 20: return "ppc";
        case 21: return "ppc64";
        case 40: return "arm";
        case 42: return "sh";
        case 62: return "x86_64";
        case 183: return "arm64";
        case 243: return "riscv";
        default: return nullptr;
    }
}

const char* type_name(uint16_t t) {
    switch (t) {
        case 1: return "relocatable";
        case 2: return "executable";
        case 3: return "shared object";
        case 4: return "core dump";
        default: return nullptr;
    }
}
}  // namespace

// Estimate on-disk ELF size as the furthest (offset + size) across all program
// segments and sections, plus the header-table ends. This is where the file
// actually reaches, so the finding owns its region and stray "\x7fELF" byte
// sequences inside its own data don't spawn extra findings. 0 if undeterminable.
//
// Every field is validated before it is trusted, so a misread header cannot
// fabricate a size. The concrete hazard is an ELF stored inside a filesystem
// that interleaves out-of-band bytes into the flat stream (a yaffs2 image with
// per-page OOB): the program/section tables then land on shifted garbage and a
// single bogus sh_offset+sh_size would otherwise claim gigabytes and mask every
// region behind it. Guards: a header table must use the class-correct entry
// size and lie within the file; section index 0 must be the mandatory SHT_NULL
// (all-zero) entry, which a misread table almost never satisfies; and each
// individual segment/section extent must fit in the file to contribute.
uint64_t elf_size(const Reader& r, size_t off, Endian e, bool is64) {
    const uint64_t avail = r.size() - off;
    auto u16 = [&](size_t o) -> uint64_t { auto v = r.at<uint16_t>(off + o, e); return v ? *v : 0; };
    auto uoff = [&](size_t o) -> uint64_t {
        if (is64) { auto v = r.at<uint64_t>(off + o, e); return v ? *v : 0; }
        auto v = r.at<uint32_t>(off + o, e);
        return v ? *v : 0;
    };

    const uint64_t phoff = is64 ? uoff(32) : uoff(28);
    const uint64_t shoff = is64 ? uoff(40) : uoff(32);
    const uint64_t phentsize = is64 ? u16(54) : u16(42);
    const uint64_t phnum = is64 ? u16(56) : u16(44);
    const uint64_t shentsize = is64 ? u16(58) : u16(46);
    const uint64_t shnum = is64 ? u16(60) : u16(48);

    const uint64_t exp_phent = is64 ? 56 : 32;  // sizeof(Elf_Phdr) by class
    const uint64_t exp_shent = is64 ? 64 : 40;  // sizeof(Elf_Shdr) by class

    // A field (offset, length) contributes only if it lies wholly in the file.
    auto fits = [&](uint64_t o, uint64_t len) { return o <= avail && len <= avail - o; };

    uint64_t end = 0;

    // Program header table + segments.
    if (phoff && phnum && phentsize == exp_phent && fits(phoff, phnum * phentsize)) {
        end = std::max(end, phoff + phnum * phentsize);
        for (uint64_t i = 0; i < phnum; ++i) {
            const uint64_t base = phoff + i * phentsize;
            const uint64_t p_offset = is64 ? uoff(base + 8) : uoff(base + 4);
            const uint64_t p_filesz = is64 ? uoff(base + 32) : uoff(base + 16);
            if (fits(p_offset, p_filesz)) end = std::max(end, p_offset + p_filesz);
        }
    }

    // Section header table + sections, gated on a valid table whose index-0 entry
    // is SHT_NULL (all zero). This rejects a table read off interleaved OOB bytes.
    if (shoff && shnum && shentsize == exp_shent && fits(shoff, shnum * shentsize)) {
        bool null0 = true;
        for (uint64_t o = 0; o < shentsize && null0; o += 4) {
            auto w = r.at<uint32_t>(off + shoff + o, e);
            if (!w || *w != 0) null0 = false;
        }
        if (null0) {
            end = std::max(end, shoff + shnum * shentsize);
            for (uint64_t i = 0; i < shnum; ++i) {
                const uint64_t base = shoff + i * shentsize;
                auto sh_type = r.at<uint32_t>(off + base + 4, e);
                if (sh_type && *sh_type == 8) continue;  // SHT_NOBITS: no file space
                const uint64_t sh_offset = is64 ? uoff(base + 24) : uoff(base + 16);
                const uint64_t sh_size = is64 ? uoff(base + 32) : uoff(base + 20);
                if (fits(sh_offset, sh_size)) end = std::max(end, sh_offset + sh_size);
            }
        }
    }
    return end;
}

bool validate_elf(ValidatorCtx& ctx) {
    const uint64_t ei_class = field(ctx.fields, "ei_class");
    const Endian e = field(ctx.fields, "ei_data") == 2 ? Endian::Big : Endian::Little;

    auto e_type = ctx.reader.at<uint16_t>(ctx.offset + 16, e);
    auto e_machine = ctx.reader.at<uint16_t>(ctx.offset + 18, e);
    if (!e_type || !e_machine) return false;

    ctx.out.endian = e;
    uint64_t sz = elf_size(ctx.reader, ctx.offset, e, ei_class == 2);
    if (sz > 0 && sz <= ctx.reader.size() - ctx.offset) ctx.out.size = sz;
    const char* mach = machine_name(*e_machine);
    ctx.out.arch = mach ? std::string(mach) : ("machine(" + std::to_string(*e_machine) + ")");
    ctx.out.arch += (ei_class == 2) ? " 64-bit" : " 32-bit";

    if (const char* ty = type_name(*e_type)) ctx.out.label = ty;

    if (mach && type_name(*e_type))
        ctx.out.set_confidence(Confidence::Consistent, "valid ELF class/type/machine");
    else
        ctx.out.set_confidence(Confidence::Structural, "ELF e_ident valid");

    detect_upx_tamper(ctx, e, ei_class == 2);
    return true;
}

// A UPX-packed ELF has its section-header table stripped (e_shoff/e_shnum == 0)
// and carries the UPX loader ident string. A clean stub is reported separately
// by the `upx` PackHeader signature; but embedded-firmware and malware samples
// routinely zero or alter the "UPX!" trailer magic so `upx -d` fails and the
// PackHeader signature cannot match. When the ident is present but no valid
// PackHeader survives, flag the ELF so the caveat is not lost.
void detect_upx_tamper(ValidatorCtx& ctx, Endian e, bool is64) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;
    const uint64_t e_shoff = is64 ? (r.at<uint64_t>(off + 40, e).value_or(0))
                                  : (r.at<uint32_t>(off + 32, e).value_or(0));
    const uint16_t e_shnum = is64 ? (r.at<uint16_t>(off + 60, e).value_or(0))
                                  : (r.at<uint16_t>(off + 48, e).value_or(0));
    if (e_shoff != 0 && e_shnum != 0) return;  // normal ELF: section table present

    const size_t end = r.size();
    if (!has_upx_ident(r, off, end)) return;               // not a UPX stub
    if (find_upx_packheader(r, off, end)) return;          // clean: `upx` sig reports it

    std::string ver = upx_release_from_ident(r, off, end);
    std::string msg = "UPX loader ident present but no valid PackHeader trailer "
                      "(the \"UPX!\" magic was zeroed or altered); standard `upx -d` "
                      "will fail. Recover the header or carve the compressed stream.";
    ctx.out.diagnostics.push_back({"warning", "upx-tampered-header", std::move(msg)});
    ctx.out.label = ver.empty() ? "UPX-packed (header tampered)"
                                : ("UPX-packed (header tampered); UPX " + ver);
}

}  // namespace ft

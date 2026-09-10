// elf.cpp — ELF header refinement validator.
// e_ident is parsed by the layout; EI_DATA (byte 5) selects the endianness for
// the multi-byte e_type (offset 16) and e_machine (offset 18).
#include "validators/elf.hpp"

#include <algorithm>
#include <string>

namespace ft {

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
uint64_t elf_size(const Reader& r, size_t off, Endian e, bool is64) {
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

    uint64_t end = 0;
    if (phoff && phentsize) end = std::max(end, phoff + phnum * phentsize);
    if (shoff && shentsize) end = std::max(end, shoff + shnum * shentsize);

    // Program segments: p_offset + p_filesz. `base` is relative to the ELF start.
    for (uint64_t i = 0; i < phnum; ++i) {
        const uint64_t base = phoff + i * phentsize;
        const uint64_t p_offset = is64 ? uoff(base + 8) : uoff(base + 4);
        const uint64_t p_filesz = is64 ? uoff(base + 32) : uoff(base + 16);
        end = std::max(end, p_offset + p_filesz);
    }
    // Sections: sh_offset + sh_size, except SHT_NOBITS (8) which occupies no file space.
    for (uint64_t i = 0; i < shnum; ++i) {
        const uint64_t base = shoff + i * shentsize;
        auto sh_type = r.at<uint32_t>(off + base + 4, e);
        if (sh_type && *sh_type == 8) continue;
        const uint64_t sh_offset = is64 ? uoff(base + 24) : uoff(base + 16);
        const uint64_t sh_size = is64 ? uoff(base + 32) : uoff(base + 20);
        end = std::max(end, sh_offset + sh_size);
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
        ctx.out.set_confidence(Confidence::Consistent,
                               "ELF file type and processor details are valid");
    else
        ctx.out.set_confidence(Confidence::Structural, "main ELF marker is valid");
    return true;
}

}  // namespace ft

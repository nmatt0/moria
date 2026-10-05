// wince_rom.cpp — Windows CE XIP ROM extraction. See wince_rom.hpp.
//
// ROM files are simple: copy the stored bytes, running them through the
// CECompress decoder when the stored size differs from the real size.
//
// Modules are the interesting half. romimage does not keep a module as a PE
// file; it keeps an E32ROMHDR (the optional-header fields that matter), an
// O32ROMHDR array (one per section: virtual size, RVA, stored size, and a
// pointer to the bytes somewhere else in the image), and the section bytes,
// each optionally CECompress-coded. Rebuilding those into a flat PE — a DOS
// stub, a COFF header, an optional header carrying the original image base and
// entry point, a section table, and every section placed so its file offset
// equals its RVA — turns 250-odd kernel modules back into files a disassembler
// opens without a loader script.
#include "extract/wince_rom.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "extract/lzx.hpp"
#include "extract/safepath.hpp"
#include "wince_rom_parse.hpp"

namespace ft {

namespace {

constexpr uint32_t kScnCompressed = 0x00002000;  // section bytes are CECompress-coded
constexpr uint32_t kScnCode = 0x00000020;        // IMAGE_SCN_CNT_CODE
constexpr uint32_t kScnWrite = 0x80000000;       // IMAGE_SCN_MEM_WRITE
constexpr uint32_t kAlign = 0x1000;
constexpr size_t kMaxSections = 96;
constexpr uint64_t kMaxModule = uint64_t(256) << 20;
constexpr uint64_t kMaxFile = uint64_t(512) << 20;

// Data-directory slots carried in the E32 ROM header, in its own order.
enum { EXP = 0, IMP, RES, EXC, SEC };

struct Obj {
    uint32_t vsize, rva, psize, dataptr, realaddr, flags;
};

void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = uint8_t(v);
    b[off + 1] = uint8_t(v >> 8);
}

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    b[off] = uint8_t(v);
    b[off + 1] = uint8_t(v >> 8);
    b[off + 2] = uint8_t(v >> 16);
    b[off + 3] = uint8_t(v >> 24);
}

// Flatten a ROM path to one safe filename ("\\windows\\nk.exe" -> "nk.exe").
std::string flat_name(const std::string& name) {
    std::string s = name;
    for (char& c : s)
        if (c == '\\') c = '/';
    const size_t slash = s.find_last_of('/');
    if (slash != std::string::npos) s = s.substr(slash + 1);
    std::string o;
    for (char c : s) {
        const unsigned char u = static_cast<unsigned char>(c);
        o += (u >= 0x20 && u < 0x7f && c != '/' && c != '"' && c != '*' && c != ':') ? c : '_';
    }
    if (o.empty() || o == "." || o == "..") o = "_unnamed";
    return o;
}

// ROM sections carry flags but no names. Recover the conventional ones from the
// data directories and the section flags so the rebuilt PE reads naturally.
std::string section_name(const Obj& o, const uint32_t dir_rva[6],
                         const uint32_t dir_size[6], std::unordered_map<std::string, int>& used) {
    std::string n;
    if (dir_size[RES] && o.rva == dir_rva[RES]) n = ".rsrc";
    else if (dir_size[EXC] && o.rva == dir_rva[EXC]) n = ".pdata";
    else if (o.flags & kScnCode) n = ".text";
    else if (o.psize == 0) n = ".bss";
    else if (o.flags & kScnWrite) n = ".data";
    else n = ".rdata";
    if (used.count(n)) {
        const std::string stem = n.substr(0, 6);
        for (int i = 2;; ++i) {
            std::string cand = stem + std::to_string(i);
            if (!used.count(cand)) {
                n = cand;
                break;
            }
        }
    }
    used[n] = 1;
    return n;
}

// Rebuild one TOC module into a flat PE. `failed` counts sections whose
// CECompress payload would not decode; those are stored raw so nothing is lost.
bool build_pe(const Reader& r, size_t base, const CeRomHeader& h, const CeModule& m,
              std::vector<uint8_t>& pe, size_t& failed) {
    const size_t e = ce_rom_offset(r, base, h, m.e32, 0x54);
    if (e == SIZE_MAX) return false;
    auto u16 = [&](size_t o) { return r.at<uint16_t>(e + o, Endian::Little).value_or(0); };
    auto u32 = [&](size_t o) { return r.at<uint32_t>(e + o, Endian::Little).value_or(0); };

    const uint16_t objcnt = u16(0x00);
    const uint16_t imgflags = u16(0x02);
    const uint32_t entryrva = u32(0x04);
    const uint32_t vbase = u32(0x08);
    const uint32_t stackmax = u32(0x10);
    const uint32_t vsize = u32(0x14);
    const uint32_t timestamp = u32(0x20);
    if (objcnt == 0 || objcnt > kMaxSections) return false;

    uint32_t dir_rva[6], dir_size[6];
    for (int i = 0; i < 6; ++i) {
        dir_rva[i] = u32(0x24 + 8 * i);
        dir_size[i] = u32(0x28 + 8 * i);
    }

    const size_t ob = ce_rom_offset(r, base, h, m.o32, size_t(objcnt) * 24);
    if (ob == SIZE_MAX) return false;
    std::vector<Obj> objs(objcnt);
    for (uint16_t i = 0; i < objcnt; ++i) {
        const size_t p = ob + size_t(i) * 24;
        auto v = [&](size_t o) { return r.at<uint32_t>(p + o, Endian::Little).value_or(0); };
        objs[i] = {v(0), v(4), v(8), v(12), v(16), v(20)};
    }

    // Resolve each section's real bytes before laying the file out.
    std::vector<std::vector<uint8_t>> blobs(objcnt);
    for (uint16_t i = 0; i < objcnt; ++i) {
        const Obj& o = objs[i];
        const size_t n = std::min(o.vsize, o.psize);
        if (n == 0) continue;
        const size_t src = ce_rom_offset(r, base, h, o.dataptr, n);
        if (src == SIZE_MAX) {
            ++failed;
            continue;
        }
        auto raw = r.bytes(src, n);
        if (!raw) {
            ++failed;
            continue;
        }
        if (o.flags & kScnCompressed) {
            auto dec = ce_decompress_rom(*raw, o.vsize);
            if (dec) {
                blobs[i] = std::move(*dec);
                continue;
            }
            ++failed;  // keep the compressed bytes rather than dropping the section
        }
        blobs[i].assign(raw->begin(), raw->end());
    }

    uint64_t end = kAlign;  // headers occupy the first page
    for (uint16_t i = 0; i < objcnt; ++i) {
        if (blobs[i].empty()) continue;
        const uint64_t e_i =
            uint64_t(objs[i].rva) + (uint64_t(blobs[i].size()) + kAlign - 1) / kAlign * kAlign;
        end = std::max(end, e_i);
    }
    if (end > kMaxModule) return false;
    pe.assign(static_cast<size_t>(end), 0);

    // DOS header: just enough to be a PE (signature + e_lfanew).
    pe[0] = 'M';
    pe[1] = 'Z';
    put16(pe, 2, 0x90);
    constexpr size_t kNt = 0x80;
    put32(pe, 0x3c, kNt);

    // COFF header. The machine id comes from the ROM's own CPU field so a MIPS
    // or SH ROM does not get mislabelled as ARM.
    std::memcpy(pe.data() + kNt, "PE\0\0", 4);
    put16(pe, kNt + 4, h.cpu ? h.cpu : 0x01c2);
    put16(pe, kNt + 6, objcnt);
    put32(pe, kNt + 8, timestamp);
    put32(pe, kNt + 12, 0);  // PointerToSymbolTable
    put32(pe, kNt + 16, 0);  // NumberOfSymbols
    put16(pe, kNt + 20, 0xe0);
    put16(pe, kNt + 22, imgflags);

    uint32_t code = 0, data = 0, text_rva = objs[0].rva;
    bool have_text = false;
    for (const Obj& o : objs) {
        if (o.flags & kScnCode) {
            code += o.psize;
            if (!have_text) {
                text_rva = o.rva;
                have_text = true;
            }
        } else {
            data += o.psize;
        }
    }

    const size_t opt = kNt + 24;
    put16(pe, opt + 0, 0x10b);  // PE32
    pe[opt + 2] = 0;            // linker version
    pe[opt + 3] = 0;
    put32(pe, opt + 4, code);
    put32(pe, opt + 8, data);
    put32(pe, opt + 12, 0);
    put32(pe, opt + 16, entryrva);
    put32(pe, opt + 20, text_rva);
    put32(pe, opt + 24, 0);
    put32(pe, opt + 28, vbase);
    put32(pe, opt + 32, kAlign);  // SectionAlignment
    put32(pe, opt + 36, kAlign);  // FileAlignment == SectionAlignment: offset == RVA
    put16(pe, opt + 40, 4);       // OS version
    put16(pe, opt + 42, 0);
    put16(pe, opt + 44, 0);  // image version
    put16(pe, opt + 46, 0);
    put16(pe, opt + 48, 4);  // subsystem version
    put16(pe, opt + 50, 0);
    put32(pe, opt + 52, 0);
    put32(pe, opt + 56, vsize);   // SizeOfImage
    put32(pe, opt + 60, kAlign);  // SizeOfHeaders
    put32(pe, opt + 64, 0);       // CheckSum
    put16(pe, opt + 68, 9);       // IMAGE_SUBSYSTEM_WINDOWS_CE_GUI
    put16(pe, opt + 70, 0);
    put32(pe, opt + 72, stackmax);
    put32(pe, opt + 76, 0x1000);
    put32(pe, opt + 80, 0x10000);
    put32(pe, opt + 84, 0x1000);
    put32(pe, opt + 88, 0);
    put32(pe, opt + 92, 16);  // NumberOfRvaAndSizes

    const size_t dd = opt + 96;
    const int order[5] = {EXP, IMP, RES, EXC, SEC};
    for (int i = 0; i < 16; ++i) {
        const uint32_t rva = i < 5 ? dir_rva[order[i]] : 0;
        const uint32_t sz = i < 5 ? dir_size[order[i]] : 0;
        put32(pe, dd + i * 8, rva);
        put32(pe, dd + i * 8 + 4, sz);
    }

    const size_t st = opt + 0xe0;
    if (st + size_t(objcnt) * 40 > kAlign) return false;  // headers must fit one page
    std::unordered_map<std::string, int> used;
    for (uint16_t i = 0; i < objcnt; ++i) {
        const Obj& o = objs[i];
        const std::string nm = section_name(o, dir_rva, dir_size, used);
        const size_t se = st + size_t(i) * 40;
        std::memcpy(pe.data() + se, nm.data(), std::min<size_t>(nm.size(), 8));
        put32(pe, se + 8, o.vsize);
        put32(pe, se + 12, o.rva);
        const uint32_t raw = static_cast<uint32_t>((blobs[i].size() + kAlign - 1) / kAlign * kAlign);
        put32(pe, se + 16, raw);
        put32(pe, se + 20, blobs[i].empty() ? 0 : o.rva);
        put32(pe, se + 24, 0);
        put32(pe, se + 28, 0);
        put16(pe, se + 32, 0);
        put16(pe, se + 34, 0);
        put32(pe, se + 36, o.flags & ~kScnCompressed);
        if (!blobs[i].empty()) {
            if (uint64_t(o.rva) + blobs[i].size() > pe.size()) return false;
            std::memcpy(pe.data() + o.rva, blobs[i].data(), blobs[i].size());
        }
    }
    return true;
}

// Give a repeated ROM name a distinct filename rather than overwriting.
std::string unique_name(std::unordered_map<std::string, int>& used, const std::string& name) {
    int& n = used[name];
    if (n++ == 0) return name;
    const size_t dot = name.find_last_of('.');
    const std::string stem = dot == std::string::npos ? name : name.substr(0, dot);
    const std::string ext = dot == std::string::npos ? std::string() : name.substr(dot);
    return stem + "_" + std::to_string(n) + ext;
}

}  // namespace

bool extract_wince_rom(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                       Extracted& out) {
    out.offset = f.offset;
    out.type = "wince_rom";
    out.root = subdir;

    CeRomHeader h;
    if (!ce_rom_header(r, f.offset, h)) {
        out.status = "error:no-romhdr";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    std::vector<CeModule> modules;
    std::vector<CeFile> files;
    ce_rom_modules(r, f.offset, h, modules);
    ce_rom_files(r, f.offset, h, files);

    size_t mod_fail = 0, sect_fail = 0, file_fail = 0;

    if (!modules.empty() && root.make_dir(subdir + "/modules")) out.dirs++;
    if (!files.empty() && root.make_dir(subdir + "/files")) out.dirs++;

    std::unordered_map<std::string, int> used_mod, used_file;
    for (const CeModule& m : modules) {
        std::vector<uint8_t> pe;
        size_t failed = 0;
        if (!build_pe(r, f.offset, h, m, pe, failed)) {
            ++mod_fail;
            out.warnings.push_back(m.name + ": module headers unreadable, skipped");
            continue;
        }
        sect_fail += failed;
        if (failed)
            out.warnings.push_back(m.name + ": " + std::to_string(failed) +
                                   " section(s) failed to decompress, stored raw");
        const std::string rel = subdir + "/modules/" + unique_name(used_mod, flat_name(m.name));
        if (!root.write_file(rel, pe, 0644)) {
            out.status = "error:write";
            return true;
        }
        out.files++;
        out.bytes += pe.size();
    }

    for (const CeFile& fe : files) {
        if (fe.comp == 0 || fe.real > kMaxFile) {
            ++file_fail;
            continue;
        }
        const size_t src = ce_rom_offset(r, f.offset, h, fe.load, fe.comp);
        if (src == SIZE_MAX) {
            ++file_fail;
            out.warnings.push_back(fe.name + ": data outside the image");
            continue;
        }
        auto raw = r.bytes(src, fe.comp);
        if (!raw) {
            ++file_fail;
            continue;
        }

        std::string name = flat_name(fe.name);
        std::vector<uint8_t> data;
        if (fe.comp != fe.real) {
            auto dec = ce_decompress_rom(*raw, fe.real);
            if (dec) {
                data = std::move(*dec);
            } else {
                // Keep the stored bytes under a marked name so nothing is lost.
                data.assign(raw->begin(), raw->end());
                name += ".cecompressed";
                ++file_fail;
                out.warnings.push_back(fe.name + ": cecompress decode failed, stored raw");
            }
        } else {
            data.assign(raw->begin(), raw->end());
        }

        const std::string rel = subdir + "/files/" + unique_name(used_file, name);
        if (!root.write_file(rel, data, 0644)) {
            out.status = "error:write";
            return true;
        }
        out.files++;
        out.bytes += data.size();
    }

    const uint64_t span = h.span();
    const size_t avail = r.size() - f.offset;
    out.consumed = span <= avail ? span : avail;

    if (out.files == 0)
        out.status = "error:empty";
    else if (mod_fail || sect_fail || file_fail)
        out.status = "partial";
    else
        out.status = "ok";
    return true;
}

}  // namespace ft

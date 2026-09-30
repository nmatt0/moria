// wince_rom_parse.hpp — Windows CE XIP ROM (ECEC / ROMHDR) table walking.
//
// A CE ROM image (nk.bin, or a Crestron .cos) begins with an ARM/MIPS branch to
// the bootstrap; at offset 0x40 sits the signature "ECEC" followed by pTOC, the
// VIRTUAL address of the ROMHDR. The ROMHDR gives the image's physical span,
// then two tables follow it:
//
//   TOCentry[nummods]   XIP modules — executables kept split into their E32/O32
//                       ROM headers plus section data, not as whole PE files.
//   FILESentry[numfiles] plain ROM files, optionally CECompress-compressed.
//
// Everything in those tables is a virtual address, so every lookup goes through
// offset_of() (addr - physfirst, relative to where the ROM starts in the file).
// Shared by the validator (which only needs the header) and the extractor.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "reader.hpp"

namespace ft {

struct CeRomHeader {
    size_t hdr_off = 0;  // file offset of the ROMHDR itself
    uint32_t ptoc = 0;   // virtual address recorded at +0x44
    uint32_t physfirst = 0, physlast = 0;
    uint32_t nummods = 0, numfiles = 0;
    uint32_t ramstart = 0, ramfree = 0, ramend = 0;
    uint32_t kflags = 0, fsram = 0;
    uint16_t cpu = 0, misc = 0;

    uint32_t span() const { return physlast - physfirst; }
};

struct CeModule {
    std::string name;
    uint32_t attr = 0;
    uint32_t size = 0;
    uint32_t e32 = 0;  // virtual address of the E32 ROM header
    uint32_t o32 = 0;  // virtual address of the O32 section table
    uint32_t load = 0;
};

struct CeFile {
    std::string name;
    uint32_t attr = 0;
    uint32_t real = 0;  // decompressed size
    uint32_t comp = 0;  // stored size (== real when not compressed)
    uint32_t load = 0;  // virtual address of the stored bytes
};

// Locate and parse the ROMHDR for a ROM starting at `base`. Returns false when
// pTOC does not resolve to a self-consistent header (a bootloader that carries
// a stale ECEC signature but no ROM, say).
bool ce_rom_header(const Reader& r, size_t base, CeRomHeader& out);

// Virtual address -> file offset, or SIZE_MAX when it falls outside the image.
size_t ce_rom_offset(const Reader& r, size_t base, const CeRomHeader& h, uint32_t addr,
                     size_t need);

// Walk the module / file tables. Entries whose name or data lies outside the
// image are skipped; both return false only if the table itself is unreadable.
bool ce_rom_modules(const Reader& r, size_t base, const CeRomHeader& h,
                    std::vector<CeModule>& out);
bool ce_rom_files(const Reader& r, size_t base, const CeRomHeader& h, std::vector<CeFile>& out);

// PE machine id -> short architecture name ("arm", "mips", ...); "" if unknown.
const char* ce_cpu_arch(uint16_t cpu);

}  // namespace ft

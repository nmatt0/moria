// cab_parse.hpp — Microsoft Cabinet (MSCF) header and table walking.
//
// A cabinet is three tables and a blob: CFHEADER, then cFolders CFFOLDERs
// (each a compression type plus a pointer to its chain of CFDATA blocks), then
// cFiles CFFILEs (each a name plus an offset INTO ITS FOLDER'S decompressed
// stream), then the CFDATA blocks themselves. Files are not individually
// compressed — a folder is one stream and its files are slices of it.
//
// Any of the three tables may carry per-structure reserved bytes whose widths
// live in the header, so every stride here is computed, never assumed.
// Shared by the validator and the extractor.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "reader.hpp"

namespace ft {

// CFHEADER.flags
constexpr uint16_t kCabPrevCabinet = 0x0001;
constexpr uint16_t kCabNextCabinet = 0x0002;
constexpr uint16_t kCabReservePresent = 0x0004;

// CFFOLDER.typeCompress, low nibble.
enum class CabComp : uint8_t { None = 0, MsZip = 1, Quantum = 2, Lzx = 3 };

struct CabHeader {
    uint32_t cb_cabinet = 0;  // total cabinet size, from the header
    uint32_t coff_files = 0;  // file offset of the first CFFILE
    uint16_t nfolders = 0;
    uint16_t nfiles = 0;
    uint16_t flags = 0;
    uint16_t set_id = 0;
    uint16_t icabinet = 0;
    uint8_t ver_major = 0, ver_minor = 0;
    uint16_t res_header = 0;  // abReserve sizes, 0 unless kCabReservePresent
    uint8_t res_folder = 0, res_data = 0;
    size_t folders_off = 0;  // file offset of the first CFFOLDER
};

struct CabFolder {
    uint32_t coff_data = 0;  // file offset of this folder's first CFDATA
    uint16_t ndata = 0;      // number of CFDATA blocks
    uint16_t type = 0;       // raw typeCompress (low nibble = codec, bits 8-12 = LZX window)
    CabComp comp() const { return static_cast<CabComp>(type & 0x0f); }
    unsigned lzx_window() const { return (type >> 8) & 0x1f; }
};

struct CabFile {
    std::string name;         // backslash-separated, as stored
    uint32_t size = 0;        // uncompressed size
    uint32_t folder_off = 0;  // offset into the folder's decompressed stream
    uint16_t ifolder = 0;
    uint16_t attribs = 0;
    uint16_t date = 0, time = 0;
};

// Parse the CFHEADER at `base`, resolving the optional reserve fields and the
// prev/next cabinet name strings so folders_off lands on the first CFFOLDER.
bool cab_header(const Reader& r, size_t base, CabHeader& out);

// Walk the folder / file tables. Both return false if the table does not fit
// inside the file; individual malformed entries are skipped.
bool cab_folders(const Reader& r, size_t base, const CabHeader& h, std::vector<CabFolder>& out);
bool cab_files(const Reader& r, size_t base, const CabHeader& h, std::vector<CabFile>& out);

const char* cab_comp_name(CabComp c);

}  // namespace ft

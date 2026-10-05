// cab_parse.cpp — MSCF header and table walking. See the header.
#include "cab_parse.hpp"

namespace ft {

namespace {

constexpr size_t kHeaderFixed = 0x24;  // CFHEADER up to (and excluding) the reserve fields
constexpr size_t kFolderFixed = 8;
constexpr size_t kFileFixed = 16;
constexpr size_t kMaxName = 512;

// Read an ASCIIZ field, advancing `off`. False if it is unterminated or absurd.
bool read_asciiz(const Reader& r, size_t& off, std::string& out, size_t limit) {
    out.clear();
    for (size_t i = 0; i < limit; ++i) {
        auto c = r.at<uint8_t>(off + i, Endian::Little);
        if (!c) return false;
        if (*c == 0) {
            off += i + 1;
            return true;
        }
        out += static_cast<char>(*c);
    }
    return false;
}

}  // namespace

bool cab_header(const Reader& r, size_t base, CabHeader& out) {
    auto u16 = [&](size_t o) { return r.at<uint16_t>(base + o, Endian::Little); };
    auto u32 = [&](size_t o) { return r.at<uint32_t>(base + o, Endian::Little); };

    auto cb = u32(0x08);
    auto coff = u32(0x10);
    auto nfold = u16(0x1a);
    auto nfile = u16(0x1c);
    auto flags = u16(0x1e);
    auto setid = u16(0x20);
    auto icab = u16(0x22);
    auto vmin = r.at<uint8_t>(base + 0x18, Endian::Little);
    auto vmaj = r.at<uint8_t>(base + 0x19, Endian::Little);
    if (!cb || !coff || !nfold || !nfile || !flags || !setid || !icab || !vmin || !vmaj)
        return false;

    out.cb_cabinet = *cb;
    out.coff_files = *coff;
    out.nfolders = *nfold;
    out.nfiles = *nfile;
    out.flags = *flags;
    out.set_id = *setid;
    out.icabinet = *icab;
    out.ver_minor = *vmin;
    out.ver_major = *vmaj;

    size_t off = base + kHeaderFixed;
    if (out.flags & kCabReservePresent) {
        auto rh = u16(0x24);
        auto rf = r.at<uint8_t>(base + 0x26, Endian::Little);
        auto rd = r.at<uint8_t>(base + 0x27, Endian::Little);
        if (!rh || !rf || !rd) return false;
        out.res_header = *rh;
        out.res_folder = *rf;
        out.res_data = *rd;
        off += 4 + out.res_header;
    }
    // Spanning-set names sit between the reserve area and the folder table.
    std::string tmp;
    if (out.flags & kCabPrevCabinet) {
        if (!read_asciiz(r, off, tmp, kMaxName)) return false;
        if (!read_asciiz(r, off, tmp, kMaxName)) return false;
    }
    if (out.flags & kCabNextCabinet) {
        if (!read_asciiz(r, off, tmp, kMaxName)) return false;
        if (!read_asciiz(r, off, tmp, kMaxName)) return false;
    }
    out.folders_off = off;

    // Basic shape: version 1.3, both tables inside the file, the file table
    // where the header says it is.
    if (out.ver_major != 1) return false;
    if (out.nfolders == 0 || out.nfiles == 0) return false;
    const size_t stride = kFolderFixed + out.res_folder;
    if (!r.bytes(out.folders_off, size_t(out.nfolders) * stride)) return false;
    if (base + size_t(out.coff_files) < out.folders_off + size_t(out.nfolders) * stride)
        return false;
    if (!r.bytes(base + out.coff_files, size_t(out.nfiles) * kFileFixed)) return false;
    return true;
}

bool cab_folders(const Reader& r, size_t base, const CabHeader& h, std::vector<CabFolder>& out) {
    const size_t stride = kFolderFixed + h.res_folder;
    if (!r.bytes(h.folders_off, size_t(h.nfolders) * stride)) return false;
    out.reserve(h.nfolders);
    for (uint16_t i = 0; i < h.nfolders; ++i) {
        const size_t e = h.folders_off + size_t(i) * stride;
        CabFolder f;
        f.coff_data = r.at<uint32_t>(e, Endian::Little).value_or(0);
        f.ndata = r.at<uint16_t>(e + 4, Endian::Little).value_or(0);
        f.type = r.at<uint16_t>(e + 6, Endian::Little).value_or(0);
        // A folder's data must start inside the cabinet.
        if (base + size_t(f.coff_data) >= r.size()) return false;
        out.push_back(f);
    }
    return true;
}

bool cab_files(const Reader& r, size_t base, const CabHeader& h, std::vector<CabFile>& out) {
    size_t off = base + h.coff_files;
    out.reserve(h.nfiles);
    for (uint16_t i = 0; i < h.nfiles; ++i) {
        auto u16 = [&](size_t o) { return r.at<uint16_t>(off + o, Endian::Little); };
        auto u32 = [&](size_t o) { return r.at<uint32_t>(off + o, Endian::Little); };
        auto size = u32(0);
        auto fo = u32(4);
        auto ifol = u16(8);
        auto date = u16(10);
        auto time = u16(12);
        auto attr = u16(14);
        if (!size || !fo || !ifol || !date || !time || !attr) return false;
        CabFile f;
        f.size = *size;
        f.folder_off = *fo;
        f.ifolder = *ifol;
        f.date = *date;
        f.time = *time;
        f.attribs = *attr;
        off += kFileFixed;
        if (!read_asciiz(r, off, f.name, kMaxName)) return false;
        if (f.name.empty()) continue;
        out.push_back(std::move(f));
    }
    return true;
}

const char* cab_comp_name(CabComp c) {
    switch (c) {
        case CabComp::None: return "none";
        case CabComp::MsZip: return "mszip";
        case CabComp::Quantum: return "quantum";
        case CabComp::Lzx: return "lzx";
    }
    return "unknown";
}

}  // namespace ft

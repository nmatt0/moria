// rae_rfp.cpp — RAE Systems / Honeywell ".RFP" firmware package validator.
//
// Layout (all integers little-endian):
//   0x00  char     magic[16]   "RAE Systems Inc."
//   0x10  u16      version     == 1
//   0x12  u32      build_id
//   0x16  char     rae[3]      "RAE"
//   0x19  u8       digest[16]
//   0x29  section table, repeated to EOF:
//           u32  name_len
//           char name[name_len]
//           u32  flags        0 = stored, 1 = LZARI-compressed
//           u32  usize        uncompressed size
//           u32  csize        stored size (== usize when stored)
//           u8   data[csize]
// The table runs IniFile, HexFile, BinFile, SIGN (with _1 variants on
// multi-image devices). Walking it yields the exact container span; a table
// that lands precisely on EOF is a strong (verified-tier) match.
#include "validators/rae_rfp.hpp"

#include <string>

namespace ft {

namespace {
constexpr size_t kHeader = 0x29;   // bytes before the first section
constexpr size_t kMaxName = 64;    // sane bound on a section name length
constexpr size_t kMaxSections = 256;
}  // namespace

bool validate_rae_rfp(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;

    // "RAE" marker at +0x16 (the struct already matched the 16-byte magic).
    static constexpr uint8_t kRae[3] = {'R', 'A', 'E'};
    if (!r.matches_at(base + 0x16, kRae)) return false;

    // Walk the section table.
    size_t off = base + kHeader;
    size_t count = 0;
    bool any_compressed = false;
    std::string first_name;

    while (count < kMaxSections) {
        auto name_len = r.at<uint32_t>(off, Endian::Little);
        if (!name_len) break;
        if (*name_len == 0 || *name_len > kMaxName) break;

        auto name = r.bytes(off + 4, *name_len);
        if (!name) break;
        bool ascii = true;
        for (uint8_t b : *name)
            if (b < 0x20 || b >= 0x7f) { ascii = false; break; }
        if (!ascii) break;

        const size_t p = off + 4 + *name_len;
        auto flags = r.at<uint32_t>(p, Endian::Little);
        auto csize = r.at<uint32_t>(p + 8, Endian::Little);
        if (!flags || !csize) break;
        if (*flags > 1) break;
        if (*flags == 1) any_compressed = true;

        if (count == 0)
            first_name.assign(reinterpret_cast<const char*>(name->data()), name->size());

        const size_t data_off = p + 12;
        if (*csize > r.size() - data_off) break;  // section runs past EOF
        off = data_off + *csize;
        ++count;

        if (off == r.size()) break;  // table lands exactly on EOF — done
    }

    if (count == 0) return false;  // no parseable section: not a real RFP

    const size_t span = off - base;
    ctx.out.size = span;
    ctx.out.version = "1";
    ctx.out.compression = any_compressed ? "lzari" : "none";
    if (!first_name.empty()) ctx.out.label = first_name;  // first section (always "IniFile")

    if (off == r.size())
        ctx.out.set_confidence(Confidence::Verified, "section list reaches the end of the file");
    else
        ctx.out.set_confidence(Confidence::Consistent, "section list could be read");
    return true;
}

}  // namespace ft

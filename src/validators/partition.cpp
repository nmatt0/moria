// partition.cpp — GPT and MBR/DOS partition-table validators. See partition.hpp.
#include "validators/partition.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "crc32.hpp"

namespace ft {

namespace {

// ---- small readers ----------------------------------------------------------
uint32_t u32(const Reader& r, size_t off) {
    auto v = r.at<uint32_t>(off, Endian::Little);
    return v ? *v : 0;
}
uint64_t u64(const Reader& r, size_t off) {
    auto v = r.at<uint64_t>(off, Endian::Little);
    return v ? *v : 0;
}

// ---- GPT partition type GUIDs (stored on disk mixed-endian) -----------------
struct GuidName {
    std::array<uint8_t, 16> guid;
    const char* name;
};

// On-disk byte order: first three fields little-endian, last two big-endian.
const std::array<GuidName, 20> kGptTypes = {{
    {{0x28,0x73,0x2A,0xC1,0x1F,0xF8,0xD2,0x11,0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B}, "EFI System"},
    {{0xAF,0x3D,0xC6,0x0F,0x83,0x84,0x72,0x47,0x8E,0x79,0x3D,0x69,0xD8,0x47,0x7D,0xE4}, "Linux filesystem"},
    {{0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7}, "Microsoft basic data"},
    {{0x6D,0xFD,0x57,0x06,0xAB,0xA4,0xC4,0x43,0x84,0xE5,0x09,0x33,0xC8,0x4B,0x4F,0x4F}, "Linux swap"},
    {{0x79,0xD3,0xD6,0xE6,0x07,0xF5,0xC2,0x44,0xA2,0x3C,0x23,0x8F,0x2A,0x3D,0xF9,0x28}, "Linux LVM"},
    {{0x48,0x61,0x68,0x21,0x49,0x64,0x6F,0x6E,0x74,0x4E,0x65,0x65,0x64,0x45,0x46,0x49}, "BIOS boot"},
    {{0x9C,0x1A,0x17,0xEF,0x0D,0xA9,0x8F,0x42,0xB4,0xC3,0x8D,0xB1,0x88,0xEA,0x4A,0x1B}, "Linux extended boot"},
    {{0x28,0x73,0x2A,0xC1,0x1F,0xF8,0xD2,0x11,0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B}, "EFI System"},
    {{0x16,0xE3,0xC9,0xE3,0x5C,0x0B,0xB8,0x4D,0x81,0x7D,0xF9,0x2D,0xF0,0x02,0x15,0xAE}, "Microsoft reserved"},
    {{0xA4,0xBB,0x94,0xDE,0xD1,0x06,0x40,0x4D,0xA1,0x6A,0xBF,0xD5,0x01,0x79,0xD6,0xAC}, "Windows recovery"},
    {{0x00,0x53,0x46,0x48,0x00,0x00,0xAA,0x11,0xAA,0x11,0x00,0x30,0x65,0x43,0xEC,0xAC}, "Apple HFS+"},
    {{0x00,0x56,0x46,0x53,0x00,0x00,0xAA,0x11,0xAA,0x11,0x00,0x30,0x65,0x43,0xEC,0xAC}, "Apple APFS"},
    {{0x5D,0xFB,0xF5,0xF4,0x28,0x48,0x4B,0xAC,0xAA,0x8F,0x30,0x09,0x60,0x63,0x71,0x6B}, "ChromeOS kernel"},
    {{0x02,0xE2,0xB8,0x3C,0x7E,0x3B,0xDD,0x47,0x8A,0x3C,0x7F,0xF2,0xA1,0x3C,0xFC,0xEC}, "ChromeOS rootfs"},
    {{0x38,0xF4,0x28,0xE6,0xD3,0x26,0xB2,0x45,0x9B,0x27,0xC1,0xC1,0x0E,0x63,0x8A,0x5C}, "Android system"},  // approx family
    {{0x06,0x9B,0x25,0xAC,0x69,0x38,0x1D,0x49,0x8D,0xF9,0xD5,0x18,0x8B,0x4C,0x35,0xA4}, "Android data"},     // approx family
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, "unused"},
    {{0x9E,0x1A,0x2D,0x38,0xC6,0x12,0x37,0x4C,0x82,0x18,0x25,0x2A,0x91,0x0F,0xF5,0x1E}, "Microsoft LDM data"},
    {{0xAA,0xC8,0x08,0x58,0x8F,0x7E,0xE0,0x42,0x85,0xD2,0xE1,0xE9,0x04,0x34,0xCF,0xB3}, "Microsoft LDM metadata"},
    {{0xA0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, "unknown"},
}};

// Canonical GUID string from the 16 on-disk bytes (fields 1-3 LE, 4-5 BE).
std::string guid_string(const uint8_t* g) {
    char b[40];
    std::snprintf(b, sizeof(b),
                  "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                  g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11],
                  g[12], g[13], g[14], g[15]);
    return b;
}

bool guid_zero(const uint8_t* g) {
    for (int i = 0; i < 16; ++i)
        if (g[i]) return false;
    return true;
}

std::string gpt_type_name(const uint8_t* g) {
    for (const auto& t : kGptTypes)
        if (std::memcmp(g, t.guid.data(), 16) == 0) return t.name;
    return guid_string(g);
}

// UTF-16LE partition name -> printable ASCII (control/non-ASCII -> '.'), NUL-stopped.
std::string utf16le_name(const Reader& r, size_t off, size_t bytes) {
    std::string s;
    for (size_t i = 0; i + 1 < bytes; i += 2) {
        auto cu = r.at<uint16_t>(off + i, Endian::Little);
        if (!cu || *cu == 0) break;
        char c = (*cu >= 0x20 && *cu < 0x7f) ? static_cast<char>(*cu) : '.';
        s.push_back(c);
    }
    return s;
}

// ---- MBR partition type bytes ----------------------------------------------
const char* mbr_type_name(uint8_t t) {
    switch (t) {
        case 0x01: return "FAT12";
        case 0x04: case 0x06: case 0x0E: return "FAT16";
        case 0x0B: case 0x0C: return "FAT32";
        case 0x07: return "NTFS/exFAT";
        case 0x05: case 0x0F: return "Extended";
        case 0x82: return "Linux swap";
        case 0x83: return "Linux";
        case 0x8E: return "Linux LVM";
        case 0xFD: return "Linux RAID";
        case 0xEF: return "EFI System";
        case 0xEE: return "GPT protective";
        case 0xA5: return "FreeBSD";
        case 0xA6: return "OpenBSD";
        case 0xA9: return "NetBSD";
        case 0xAF: return "Apple HFS+";
        case 0xDA: return "non-FS data";
        case 0x53: return "OnTrack";
        case 0xC0: return "Novell/DR-DOS";
        default: return nullptr;
    }
}

}  // namespace

bool validate_gpt(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;  // GPT header start (LBA1)

    uint32_t rev = u32(r, off + 0x08);
    uint32_t hsize = u32(r, off + 0x0C);
    uint64_t my_lba = u64(r, off + 0x18);
    if (rev != 0x00010000u) return false;      // GPT revision 1.0
    if (hsize < 92 || hsize > 4096) return false;
    if (my_lba == 0 || off % my_lba != 0) return false;
    size_t sector = off / my_lba;
    if (sector != 512 && sector != 4096) return false;
    if (my_lba != 1) return false;             // a backup header (at disk end) — GPT primary owns the map

    // Header CRC32: over header[0..hsize] with the crc field (0x10..0x14) zeroed.
    auto hdr = r.bytes(off, hsize);
    if (!hdr) return false;
    uint32_t stored_hcrc = u32(r, off + 0x10);
    std::vector<uint8_t> h(hdr->begin(), hdr->end());
    h[0x10] = h[0x11] = h[0x12] = h[0x13] = 0;
    const bool header_ok = crc32_ieee(h) == stored_hcrc;

    uint64_t pe_lba = u64(r, off + 0x48);
    uint32_t n_ent = u32(r, off + 0x50);
    uint32_t ent_sz = u32(r, off + 0x54);
    uint32_t arr_crc = u32(r, off + 0x58);
    if (pe_lba == 0 || n_ent == 0 || n_ent > 4096) return false;
    if (ent_sz < 128 || ent_sz > 4096 || (ent_sz % 8) != 0) return false;

    const uint64_t arr_off = pe_lba * sector;
    const uint64_t arr_bytes = static_cast<uint64_t>(n_ent) * ent_sz;
    auto arr = r.bytes(arr_off, arr_bytes);
    const bool array_ok = arr && crc32_ieee(*arr) == arr_crc;

    // Reject a stray "EFI PART" (e.g. inside a filesystem): a real primary header
    // has a valid header CRC.
    if (!header_ok && !array_ok) return false;

    Finding& out = ctx.out;
    out.type = "gpt";
    out.category = "container";
    out.endian = Endian::Little;
    out.size = (arr_off + arr_bytes) - off;  // header + entry array (primary GPT metadata)

    // Decode used partition entries into members.
    size_t nparts = 0;
    if (arr) {
        for (uint32_t i = 0; i < n_ent; ++i) {
            const uint64_t e = arr_off + static_cast<uint64_t>(i) * ent_sz;
            auto gb = r.bytes(e, 16);
            if (!gb) break;
            const uint8_t* g = gb->data();
            if (guid_zero(g)) continue;  // unused entry
            uint64_t first = u64(r, e + 0x20);
            uint64_t last = u64(r, e + 0x28);
            if (first == 0 || last < first) continue;
            std::string tname = gpt_type_name(g);
            std::string pname = utf16le_name(r, e + 0x38, 72);
            if (pname.empty()) pname = "p" + std::to_string(i + 1);
            Member m;
            m.name = pname;
            m.note = tname;
            m.offset = static_cast<size_t>(first * sector);
            m.size = static_cast<size_t>((last - first + 1) * sector);
            out.members.push_back(std::move(m));
            ++nparts;
        }
    }

    const char* tier_reason;
    Confidence tier;
    if (header_ok && array_ok) {
        tier = Confidence::Verified;
        tier_reason = "GPT header + entry-array CRC32 verified";
    } else if (header_ok) {
        tier = Confidence::Consistent;
        tier_reason = "GPT header CRC32 verified (entry array unreadable/mismatch)";
    } else {
        tier = Confidence::Structural;
        tier_reason = "GPT entry-array CRC32 verified (header CRC mismatch)";
    }
    out.set_confidence(tier, std::string(tier_reason) + ": " + std::to_string(nparts) +
                                 (nparts == 1 ? " partition" : " partitions"));
    return true;
}

bool validate_mbr(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;  // sector start (boot signature at off+0x1FE)
    constexpr size_t SECTOR = 512;
    // A real MBR/EBR boot record is sector-aligned; the alignment guard rejects the
    // vast majority of stray 0x55AA trailers cheaply (both an FP and a perf win).
    if (off % SECTOR != 0) return false;
    const uint64_t disk_sectors = r.size() / SECTOR;

    struct PE { uint8_t boot, type; uint32_t lba, cnt; };
    PE e[4];
    int used = 0, protective = 0;
    for (int i = 0; i < 4; ++i) {
        const size_t b = off + 0x1BE + static_cast<size_t>(i) * 16;
        auto boot = r.at<uint8_t>(b + 0, Endian::Little);
        auto type = r.at<uint8_t>(b + 4, Endian::Little);
        if (!boot || !type) return false;
        if (*boot != 0x00 && *boot != 0x80) return false;  // invalid boot flag -> not an MBR (FP guard)
        e[i] = {*boot, *type, u32(r, b + 8), u32(r, b + 12)};
        if (e[i].type != 0) {
            ++used;
            if (e[i].type == 0xEE) ++protective;
        }
    }
    if (used == 0) return false;
    // A bare protective MBR (a single 0xEE spanning the disk) means a GPT follows;
    // reject so the GPT owns the labeled map rather than emitting a redundant row.
    if (used == 1 && protective == 1) return false;

    // Sanity / FP guard: count primaries that sit within the disk with a nonzero
    // start. Require at least one, so a random 0x55AA trailer is rejected.
    int sane = 0;
    for (int i = 0; i < 4; ++i) {
        if (e[i].type == 0 || e[i].type == 0xEE) continue;
        const bool extended = e[i].type == 0x05 || e[i].type == 0x0F;
        if (e[i].lba == 0) continue;                       // a table entry never starts at LBA0
        if (disk_sectors && e[i].lba >= disk_sectors) continue;
        if (!extended && e[i].cnt == 0) continue;          // a primary needs a nonzero size
        ++sane;                                            // a valid primary or extended entry
    }
    if (sane == 0) return false;

    Finding& out = ctx.out;
    out.type = "mbr";
    out.category = "container";
    out.endian = Endian::Little;
    out.size = SECTOR;

    int pno = 0;
    size_t nparts = 0;
    for (int i = 0; i < 4; ++i) {
        if (e[i].type == 0) continue;
        ++pno;
        const bool extended = e[i].type == 0x05 || e[i].type == 0x0F;
        const char* tn = mbr_type_name(e[i].type);
        char note[48];
        if (tn)
            std::snprintf(note, sizeof(note), "%s (0x%02X)", tn, e[i].type);
        else
            std::snprintf(note, sizeof(note), "type 0x%02X", e[i].type);
        Member m;
        m.name = "p" + std::to_string(pno);
        m.note = note;
        m.offset = static_cast<size_t>(e[i].lba) * SECTOR;
        m.size = static_cast<size_t>(e[i].cnt) * SECTOR;
        out.members.push_back(std::move(m));
        ++nparts;

        // Walk the extended-partition EBR chain for logical partitions. Each EBR
        // has two entries: [0] the logical partition (relative to this EBR), [1]
        // the next EBR (relative to the extended partition's start). Bounded.
        if (extended) {
            const uint64_t ext_base = e[i].lba;
            uint64_t ebr = ext_base;
            for (int guard = 0; guard < 128; ++guard) {
                const size_t eb = static_cast<size_t>(ebr) * SECTOR;
                auto sig = r.at<uint16_t>(eb + 0x1FE, Endian::Little);
                if (!sig || *sig != 0xAA55) break;
                auto ltype = r.at<uint8_t>(eb + 0x1BE + 4, Endian::Little);
                uint32_t llba = u32(r, eb + 0x1BE + 8);
                uint32_t lcnt = u32(r, eb + 0x1BE + 12);
                if (ltype && *ltype != 0 && lcnt) {
                    ++pno;
                    const char* ltn = mbr_type_name(*ltype);
                    char lnote[48];
                    if (ltn)
                        std::snprintf(lnote, sizeof(lnote), "%s (0x%02X, logical)", ltn, *ltype);
                    else
                        std::snprintf(lnote, sizeof(lnote), "type 0x%02X (logical)", *ltype);
                    Member m2;
                    m2.name = "p" + std::to_string(pno);
                    m2.note = lnote;
                    m2.offset = static_cast<size_t>(ebr + llba) * SECTOR;
                    m2.size = static_cast<size_t>(lcnt) * SECTOR;
                    out.members.push_back(std::move(m2));
                    ++nparts;
                }
                uint8_t ntype = 0;
                if (auto nt = r.at<uint8_t>(eb + 0x1CE + 4, Endian::Little)) ntype = *nt;
                uint32_t nlba = u32(r, eb + 0x1CE + 8);
                if (nlba == 0 || (ntype != 0x05 && ntype != 0x0F)) break;
                uint64_t next = ext_base + nlba;
                if (next <= ebr) break;  // no forward progress -> stop
                ebr = next;
            }
        }
    }

    const bool strong = sane >= 1;
    out.set_confidence(strong ? Confidence::Consistent : Confidence::Structural,
                       "MBR/DOS partition table: " + std::to_string(nparts) +
                           (nparts == 1 ? " partition" : " partitions"));
    return true;
}

}  // namespace ft

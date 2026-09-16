// esp32_part.cpp — ESP-IDF partition table validator. See esp32_part.hpp.
//
// The table lives at flash offset 0x8000 by default (a custom
// CONFIG_PARTITION_TABLE_OFFSET moves it, always 4 KB-aligned). Entries are 32
// bytes, little-endian: u16 magic 0xAA50, u8 type, u8 subtype, u32 offset,
// u32 size, 16-byte NUL-padded label. The list ends with an MD5 entry
// (magic 0xEBEB, 14 bytes 0xFF, 16-byte digest) or an erased (0xFF) entry, and
// is capped at 0xC00 bytes (95 entries + MD5). The 2-byte magic is the only
// anchor, so the validator is the filter: entries must be 4 KB-aligned,
// non-overlapping, within a sane flash bound, and at least two must carry a
// recognized app/data type+subtype. Partitions may legitimately extend past
// EOF (a factory image omits data regions flashed separately), so in-file
// bounds are only required for a single entry. Each partition is emitted as a
// member (labeled region); the content inside the regions is identified by the
// normal pipeline, exactly like GPT/MBR.
#include "validators/esp32_part.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace ft {

namespace {

constexpr uint16_t kEntryMagic = 0x50AA;  // on-disk bytes AA 50, read little-endian
constexpr uint16_t kMd5Magic = 0xEBEB;
constexpr size_t kMaxEntries = 96;  // 0xC00 table / 32-byte entries
constexpr uint64_t kMaxFlash = uint64_t(64) << 20;  // generous bound (real flash <= 16 MiB)

struct EspPart {
    uint8_t type, subtype;
    uint32_t offset, size;
    std::string label;
    bool recognized;  // app/data with a known subtype
};

uint32_t u32(const Reader& r, size_t off) {
    auto v = r.at<uint32_t>(off, Endian::Little);
    return v ? *v : 0;
}

const char* type_name(uint8_t t) {
    switch (t) {
        case 0x00: return "app";
        case 0x01: return "data";
        case 0x02: return "bootloader";
        case 0x03: return "partition_table";
        default: return nullptr;
    }
}

// Keep in sync with esp_partition_subtype_t / gen_esp32part.py SUBTYPES.
const char* subtype_name(uint8_t type, uint8_t st, char* buf, size_t buflen) {
    if (type == 0x00) {  // app
        if (st == 0x00) return "factory";
        if (st >= 0x10 && st <= 0x1F) {
            std::snprintf(buf, buflen, "ota_%u", st - 0x10);
            return buf;
        }
        if (st == 0x20) return "test";
        if (st == 0x30) return "tee_0";
        if (st == 0x31) return "tee_1";
    } else if (type == 0x01) {  // data
        switch (st) {
            case 0x00: return "ota";
            case 0x01: return "phy";
            case 0x02: return "nvs";
            case 0x03: return "coredump";
            case 0x04: return "nvs_keys";
            case 0x05: return "efuse";
            case 0x06: return "undefined";
            case 0x80: return "esphttpd";
            case 0x81: return "fat";
            case 0x82: return "spiffs";
            case 0x83: return "littlefs";
            case 0x90: return "tee_ota";
            default: break;
        }
    } else if (type == 0x02 || type == 0x03) {  // bootloader / partition_table
        switch (st) {
            case 0x00: return "primary";
            case 0x01: return "ota";
            default: break;
        }
        if (type == 0x02 && st == 0x02) return "recovery";
    }
    return nullptr;
}

// NUL-stopped printable label; empty if the field is unusable.
std::string label_of(const Reader& r, size_t off) {
    auto b = r.bytes(off, 16);
    if (!b) return "";
    std::string s;
    for (uint8_t c : *b) {
        if (c == 0) break;
        if (c < 0x20 || c >= 0x7F) return "";
        s.push_back(static_cast<char>(c));
    }
    return s;
}

}  // namespace

bool validate_esp32_partition_table(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;
    // A partition table is flashed at a 4 KB-aligned offset (0x8000 default).
    // The alignment guard rejects the bulk of stray 0xAA50 words cheaply.
    if (off % 0x1000 != 0) return false;

    std::vector<EspPart> parts;
    bool md5_term = false;
    size_t used = 0;  // bytes of table consumed (through the terminator)
    for (size_t i = 0; i < kMaxEntries; ++i) {
        const size_t e = off + i * 32;
        auto magic = r.at<uint16_t>(e, Endian::Little);
        if (!magic) return false;  // table runs past EOF mid-list
        if (*magic == kMd5Magic) {
            // MD5 terminator: 14 bytes 0xFF, then the 16-byte digest.
            auto pad = r.bytes(e + 2, 14);
            if (!pad) return false;
            for (uint8_t c : *pad)
                if (c != 0xFF) return false;
            md5_term = true;
            used = (i + 1) * 32;
            break;
        }
        if (*magic == 0xFFFF) { used = i * 32; break; }  // erased entry = end
        if (*magic != kEntryMagic) return false;

        auto type = r.at<uint8_t>(e + 2, Endian::Little);
        auto subtype = r.at<uint8_t>(e + 3, Endian::Little);
        if (!type || !subtype) return false;
        EspPart p{*type, *subtype, u32(r, e + 4), u32(r, e + 8), label_of(r, e + 12), false};
        if (p.type == 0xFF || p.subtype == 0xFF) return false;
        if (p.label.empty()) return false;
        if (p.offset % 0x1000 != 0) return false;        // offsets are sector-aligned
        if (p.size == 0 || p.size > kMaxFlash) return false;
        if (p.offset >= kMaxFlash) return false;
        if (p.type == 0x00 && p.size % 0x1000 != 0) return false;  // app sizes are aligned
        char buf[8];
        p.recognized = (p.type == 0x00 || p.type == 0x01) &&
                       subtype_name(p.type, p.subtype, buf, sizeof(buf)) != nullptr;
        parts.push_back(std::move(p));
    }
    if (used == 0) return false;  // no terminator within the entry cap

    // "Multiple consistent entries": at least two, at least two recognized
    // app/data partitions, and no two regions overlapping.
    if (parts.size() < 2) return false;
    size_t recognized = 0;
    for (const auto& p : parts)
        if (p.recognized) ++recognized;
    if (recognized < 2) return false;
    std::vector<EspPart> sorted = parts;
    std::sort(sorted.begin(), sorted.end(),
              [](const EspPart& a, const EspPart& b) { return a.offset < b.offset; });
    uint64_t prev_end = 0;
    bool in_file = false;
    for (const auto& p : sorted) {
        if (p.offset < prev_end) return false;  // overlapping
        prev_end = static_cast<uint64_t>(p.offset) + p.size;
        if (p.offset < r.size()) in_file = true;
    }
    if (!in_file) return false;

    Finding& out = ctx.out;
    out.type = "esp32_partition_table";
    out.category = "container";
    out.endian = Endian::Little;
    out.size = used;

    for (const auto& p : parts) {
        char stbuf[8];
        const char* tn = type_name(p.type);
        const char* stn = subtype_name(p.type, p.subtype, stbuf, sizeof(stbuf));
        char note[40];
        char tbuf[8];
        if (!tn) {
            std::snprintf(tbuf, sizeof(tbuf), "0x%02x", p.type);
            tn = tbuf;
        }
        if (!stn) {
            std::snprintf(stbuf, sizeof(stbuf), "0x%02x", p.subtype);
            stn = stbuf;
        }
        std::snprintf(note, sizeof(note), "%s/%s", tn, stn);
        Member m;
        m.name = p.label;
        m.note = note;
        m.offset = p.offset;
        m.size = p.size;
        out.members.push_back(std::move(m));
    }

    out.set_confidence(Confidence::Consistent,
                       "ESP-IDF partition table: " + std::to_string(parts.size()) +
                           (parts.size() == 1 ? " partition" : " partitions") +
                           (md5_term ? ", MD5 terminator" : ", no MD5 terminator"));
    return true;
}

}  // namespace ft

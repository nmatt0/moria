// otra_format.hpp — Artosyn OTRA firmware image parser (header + partition/segment
// tables), shared by the validator and the extractor. Header-only, no I/O beyond
// the bounds-checked Reader. See signatures/otra.toml for the on-disk layout.
//
// Two body layouts exist. `parse_otra` decodes the header for both; `parse_otra_tables`
// additionally walks the partition and segment tables and reports whether the image
// is the "segmented" subtype (populated tables + a contiguous LZO payload chain that
// spans the body) or the "flat" subtype (a raw flash image with empty tables).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "reader.hpp"

namespace ft {

namespace otra {

constexpr size_t kHeaderEnd = 0x220;  // header + hash + signature; body starts here
constexpr size_t kHashOff = 0x100, kHashLen = 0x20;
constexpr size_t kSigOff = 0x120, kSigLen = 0x100;
constexpr size_t kPartEntry = 0x34;   // name[0x20] + u64 flash_off + u64 cap + u32 flags
constexpr size_t kSegEntry = 0x20;    // u64 file_off + u64 flash_off + u64 data_len + u64 flash_len
constexpr size_t kMaxParts = 64;
constexpr size_t kMaxSegs = 512;

struct Header {
    uint8_t ver = 0;
    uint8_t compress = 0;
    uint8_t hashsize = 0;
    uint16_t siglen = 0;
    uint64_t body_size = 0;   // field @0x10; should equal filesize - 0x220
    uint64_t region1 = 0;
    uint64_t region2 = 0;
    uint16_t npart = 0;
    uint16_t nseg = 0;
    std::string version;      // ASCII build string at 0x80 (e.g. "0.00.00")
    size_t part_off = 0, seg_off = 0, pay_off = 0;  // absolute offsets in the image
};

struct Partition {
    std::string name;
    uint64_t flash_off = 0;
    uint64_t capacity = 0;
    uint32_t flags = 0;
};

struct Segment {
    uint64_t file_off = 0;    // absolute offset of the (compressed) payload in the image
    uint64_t flash_off = 0;   // on-flash target, used to match a segment to its partition
    uint64_t data_len = 0;    // compressed size
    uint64_t flash_len = 0;   // decompressed / on-flash size
};

struct Tables {
    bool segmented = false;               // populated tables + valid payload chain
    bool chain_spans_body = false;        // last payload ends exactly at EOF
    std::vector<Partition> parts;
    std::vector<Segment> segs;
};

// Decode the fixed header. `base` is the offset of the 'OTRA' magic (0 in practice).
inline std::optional<Header> parse_otra(const Reader& r, size_t base) {
    auto magic = r.bytes(base, 4);
    if (!magic || (*magic)[0] != 'O' || (*magic)[1] != 'T' || (*magic)[2] != 'R' ||
        (*magic)[3] != 'A')
        return std::nullopt;

    auto ver = r.at<uint8_t>(base + 0x04, Endian::Little);
    auto compress = r.at<uint8_t>(base + 0x05, Endian::Little);
    auto hashsize = r.at<uint8_t>(base + 0x0a, Endian::Little);
    auto siglen = r.at<uint16_t>(base + 0x0e, Endian::Little);
    auto body_size = r.at<uint32_t>(base + 0x10, Endian::Little);
    auto region1 = r.at<uint32_t>(base + 0x18, Endian::Little);
    auto region2 = r.at<uint32_t>(base + 0x1c, Endian::Little);
    auto npart = r.at<uint16_t>(base + 0x20, Endian::Little);
    auto nseg = r.at<uint16_t>(base + 0x22, Endian::Little);
    if (!ver || !compress || !hashsize || !siglen || !body_size || !region1 || !region2 ||
        !npart || !nseg)
        return std::nullopt;

    Header h;
    h.ver = *ver;
    h.compress = *compress;
    h.hashsize = *hashsize;
    h.siglen = *siglen;
    h.body_size = *body_size;
    h.region1 = *region1;
    h.region2 = *region2;
    h.npart = *npart;
    h.nseg = *nseg;

    // ASCII build string at 0x80 (16 bytes max), when present and printable.
    if (auto vs = r.bytes(base + 0x80, 16)) {
        std::string s;
        for (uint8_t c : *vs) {
            if (c == 0) break;
            if (c < 0x20 || c >= 0x7f) { s.clear(); break; }
            s += static_cast<char>(c);
        }
        h.version = s;
    }

    // Table offsets: region1 precedes region2, tables follow both (RE'd pointer math).
    h.part_off = base + kHeaderEnd + h.region1 + h.region2;
    h.seg_off = h.part_off + size_t(h.npart) * kPartEntry;
    h.pay_off = h.seg_off + size_t(h.nseg) * kSegEntry;
    return h;
}

// Walk the partition + segment tables and classify the subtype. Never throws;
// on a flat/opaque image it returns Tables{segmented=false} with empty vectors.
inline Tables parse_otra_tables(const Reader& r, size_t base, const Header& h) {
    Tables t;
    if (h.npart == 0 || h.npart > kMaxParts || h.nseg == 0 || h.nseg > kMaxSegs) return t;
    if (h.pay_off > r.size()) return t;

    std::vector<Partition> parts;
    for (size_t i = 0; i < h.npart; ++i) {
        const size_t o = h.part_off + i * kPartEntry;
        auto name = r.bytes(o, 0x20);
        auto flash_off = r.at<uint64_t>(o + 0x20, Endian::Little);
        auto capacity = r.at<uint64_t>(o + 0x28, Endian::Little);
        auto flags = r.at<uint32_t>(o + 0x30, Endian::Little);
        if (!name || !flash_off || !capacity || !flags) return t;
        Partition p;
        for (uint8_t c : *name) {
            if (c == 0) break;
            p.name += static_cast<char>(c);
        }
        p.flash_off = *flash_off;
        p.capacity = *capacity;
        p.flags = *flags;
        parts.push_back(std::move(p));
    }

    std::vector<Segment> segs;
    uint64_t chain = h.pay_off;  // payloads are laid out contiguously from here
    for (size_t i = 0; i < h.nseg; ++i) {
        const size_t o = h.seg_off + i * kSegEntry;
        auto file_off = r.at<uint64_t>(o + 0x00, Endian::Little);
        auto flash_off = r.at<uint64_t>(o + 0x08, Endian::Little);
        auto data_len = r.at<uint64_t>(o + 0x10, Endian::Little);
        auto flash_len = r.at<uint64_t>(o + 0x18, Endian::Little);
        if (!file_off || !data_len || !flash_len) return t;
        // A populated segment must sit inside the file, after the tables, and follow
        // the previous one with no gap (the flat subtype fails here: file_off == 0).
        if (*file_off != chain) return t;
        if (*data_len > r.size() - *file_off) return t;
        Segment s;
        s.file_off = *file_off;
        s.flash_off = flash_off ? *flash_off : 0;
        s.data_len = *data_len;
        s.flash_len = *flash_len;
        chain = *file_off + *data_len;
        segs.push_back(s);
    }

    t.segmented = true;
    t.chain_spans_body = (chain == r.size());
    t.parts = std::move(parts);
    t.segs = std::move(segs);
    return t;
}

// Segments whose flash_off falls within a partition's [flash_off, flash_off+capacity).
inline std::vector<const Segment*> segments_of(const Partition& p,
                                               const std::vector<Segment>& segs) {
    std::vector<const Segment*> sel;
    for (const auto& s : segs)
        if (s.flash_off >= p.flash_off && s.flash_off < p.flash_off + p.capacity) sel.push_back(&s);
    return sel;
}

}  // namespace otra
}  // namespace ft

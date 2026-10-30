// ihex.cpp — Intel HEX image decoder. See ihex.hpp.
//
// Records are parsed from the finding offset. Absolute addresses are rebuilt
// across the base-setting record types (02 extended segment, 04 extended
// linear); type 00 carries data, type 01 ends the image, 03/05 are entry-point
// records with no bearing on the image. Programmed bytes are placed by absolute
// address: a run of contiguous (or near-contiguous) bytes becomes one output
// segment, and a gap wider than a small alignment tolerance starts a new one,
// so a sparse image (vector table at 0x0, app at 0x8000000, ...) is emitted as
// separate blobs instead of 0xFF-padding across a multi-megabyte hole.
#include "extract/ihex.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

// Decoded-output ceiling. Hex images are MCU-scale firmware; this is generous
// for the domain and still bounds a pathological or hostile record stream.
constexpr uint64_t MAX_OUT = uint64_t(256) << 20;  // 256 MiB
// Gap up to this many bytes is filled with 0xFF (flash erase state) and kept in
// the current segment; a wider gap starts a new segment.
constexpr uint64_t PAD_TOL = 16;
// Ceiling on distinct segments, so a stream that skips around wildly can't spawn
// unbounded output files.
constexpr size_t MAX_SEGMENTS = 4096;

// Parse two ASCII hex digits at p[i]. Returns nullopt on a non-hex byte.
std::optional<uint8_t> hex8(const uint8_t* p, size_t n, size_t i) {
    if (i + 2 > n) return std::nullopt;
    uint8_t v = 0;
    for (size_t k = 0; k < 2; ++k) {
        uint8_t c = p[i + k];
        if (c >= '0' && c <= '9') v = static_cast<uint8_t>(v * 16 + (c - '0'));
        else if (c >= 'a' && c <= 'f') v = static_cast<uint8_t>(v * 16 + (c - 'a' + 10));
        else if (c >= 'A' && c <= 'F') v = static_cast<uint8_t>(v * 16 + (c - 'A' + 10));
        else return std::nullopt;
    }
    return v;
}

struct Segment {
    uint64_t base = 0;
    std::vector<uint8_t> buf;
};

}  // namespace

bool extract_ihex(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out) {
    out.offset = f.offset;
    out.type = "ihex";
    out.root = subdir;

    if (f.offset >= r.size()) {
        out.status = "error:empty";
        return true;
    }
    auto span = r.bytes(static_cast<size_t>(f.offset), static_cast<size_t>(r.size() - f.offset));
    if (!span) {
        out.status = "error:read";
        return true;
    }
    const uint8_t* p = span->data();
    const size_t n = span->size();

    std::vector<Segment> segs;
    uint64_t base = 0;        // current extended-address base
    uint64_t total = 0;       // decoded bytes placed so far
    bool saw_eof = false;     // a type-01 record ended the image
    bool overflow = false;    // a cap tripped
    size_t consumed = 0;      // input bytes walked, up to and incl. the EOF record

    // Place `len` bytes (at `data`) at absolute address `abs` into the segment
    // list, honoring the gap tolerance. Returns false if a cap trips.
    auto place = [&](uint64_t abs, const uint8_t* data, size_t len) -> bool {
        if (total + len > MAX_OUT) { overflow = true; return false; }
        Segment* s = segs.empty() ? nullptr : &segs.back();
        bool fresh = !s || abs < s->base || (abs - s->base) > s->buf.size() + PAD_TOL;
        if (fresh) {
            if (segs.size() >= MAX_SEGMENTS) { overflow = true; return false; }
            segs.push_back(Segment{abs, {}});
            s = &segs.back();
        }
        size_t off = static_cast<size_t>(abs - s->base);
        if (off + len > s->buf.size()) s->buf.resize(off + len, 0xFF);  // 0xFF-pad any gap
        for (size_t i = 0; i < len; ++i) s->buf[off + i] = data[i];
        total += len;
        return true;
    };

    size_t i = 0;
    while (i < n) {
        if (p[i] != ':') {                 // skip whitespace / line breaks between records
            if (p[i] == '\r' || p[i] == '\n' || p[i] == ' ' || p[i] == '\t') { ++i; continue; }
            break;                         // any other byte ends the hex region
        }
        size_t rec = i;                    // record start (the ':')
        auto bc = hex8(p, n, i + 1);
        auto ah = hex8(p, n, i + 3);
        auto al = hex8(p, n, i + 5);
        auto tt = hex8(p, n, i + 7);
        if (!bc || !ah || !al || !tt) break;
        const size_t count = *bc;
        const size_t need = 1 + 2 * (4 + count + 1);  // ':' + bc,addr(2),type,data,cksum
        if (i + need > n) break;
        uint32_t sum = *bc + *ah + *al + *tt;
        std::vector<uint8_t> data;
        data.reserve(count);
        bool ok = true;
        for (size_t k = 0; k < count; ++k) {
            auto d = hex8(p, n, i + 9 + 2 * k);
            if (!d) { ok = false; break; }
            sum += *d;
            data.push_back(*d);
        }
        if (!ok) break;
        auto ck = hex8(p, n, i + 9 + 2 * count);
        if (!ck || ((sum + *ck) & 0xFF) != 0) break;  // bad checksum ends parsing

        const uint16_t addr = static_cast<uint16_t>((*ah << 8) | *al);
        switch (*tt) {
            case 0x00:  // data
                if (!place(base + addr, data.data(), data.size())) { i = rec; goto done; }
                break;
            case 0x01:  // end of file
                i = rec + need;
                saw_eof = true;
                goto done;
            case 0x02:  // extended segment address: base = seg << 4
                if (data.size() == 2) base = static_cast<uint64_t>((data[0] << 8) | data[1]) << 4;
                break;
            case 0x04:  // extended linear address: base = lin << 16
                if (data.size() == 2) base = static_cast<uint64_t>((data[0] << 8) | data[1]) << 16;
                break;
            case 0x03:  // start segment address (CS:IP) — entry point, no image bytes
            case 0x05:  // start linear address (EIP) — entry point, no image bytes
            default:
                break;
        }
        i += need;
    }
done:
    consumed = i;

    // A stream that produced no data records is not a standard Intel HEX image
    // we can materialize (e.g. the Tuya .H16 wide-field variant the validator
    // admits at structural tier). Report cleanly rather than writing nothing.
    if (segs.empty()) {
        out.status = "partial";
        return true;
    }
    out.consumed = consumed;

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    bool wrote = false;
    for (const Segment& s : segs) {
        char name[48];
        std::snprintf(name, sizeof(name), "image_%08llx.bin",
                      static_cast<unsigned long long>(s.base));
        if (root.write_file(subdir + "/" + name, s.buf, 0644)) {
            out.files++;
            out.bytes += s.buf.size();
            wrote = true;
        }
    }
    if (!wrote) {
        out.status = "error:write";
        return true;
    }
    if (overflow)
        out.warnings.push_back("size-capped: decoded image exceeds 256 MiB or 4096 segments");
    else if (!saw_eof)
        out.warnings.push_back("no EOF record: decoded to end of hex text");
    out.status = overflow ? "partial" : "ok";
    return true;
}

}  // namespace ft

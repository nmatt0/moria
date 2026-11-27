// sonicare_upg.cpp — Philips Sonicare ".upg" firmware container extraction.
//
// Re-reads payload_size (u32 LE @+0x08) and header_length (u16 LE @+0x0E)
// directly rather than trusting any pre-parsed fields, matching this codebase's
// other extractors. Writes header.bin / payload.bin / trailer.bin verbatim —
// no decoding, since the firmware body past payload offset 0xec is encrypted
// and the key lives on the toothbrush MCU.
//
// Also writes a sonicare_upg-info.txt sidecar holding the payload's 236-byte
// plaintext header, the same way the FIT extractor records verified-boot
// structure: the three ASCII name fields and the component record are the only
// human-readable description of what the encrypted body is, and splitting the
// container into raw .bin pieces would otherwise bury them. Structural only,
// it serializes the bytes and names the offsets it cannot explain.
#include "extract/sonicare_upg.hpp"

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {
constexpr size_t kTrailer = 16;
constexpr size_t kPlainHeader = 0xec;  // payload bytes before the encrypted body
constexpr size_t kNameField = 64;

std::string hex_of(std::span<const uint8_t> b) {
    static const char* kDigits = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b) {
        s += kDigits[c >> 4];
        s += kDigits[c & 0xF];
    }
    return s;
}

// A NUL-padded ASCII field, rendered for the sidecar. Non-printable bytes make
// it unusable as a name, so fall back to hex rather than emitting raw bytes.
std::string ascii_field(std::span<const uint8_t> b) {
    std::string s;
    for (uint8_t c : b) {
        if (c == 0) break;
        if (c < 0x20 || c >= 0x7f) return "<non-ascii> " + hex_of(b);
        s += static_cast<char>(c);
    }
    return "\"" + s + "\"";
}

std::string u32_line(const Reader& r, size_t off) {
    auto v = r.at<uint32_t>(off, Endian::Little);
    return v ? std::to_string(*v) : std::string("<unreadable>");
}

// Serialize the payload's plaintext header. Field names are the offsets, not
// guesses: only the component name and the tag have a known meaning.
void write_info(const Reader& r, size_t payload_off, uint32_t payload_size, SafeRoot& root,
                const std::string& subdir, Extracted& out) {
    if (payload_size < kPlainHeader) return;

    char buf[128];
    std::string t = "Philips Sonicare .upg payload header\n\n";
    std::snprintf(buf, sizeof(buf), "  payload_size  %u bytes\n", payload_size);
    t += buf;
    std::snprintf(buf, sizeof(buf), "  plaintext     %zu bytes (payload +0x00 .. +0x%zx)\n",
                  kPlainHeader, kPlainHeader - 1);
    t += buf;
    std::snprintf(buf, sizeof(buf), "  encrypted     %u bytes (payload +0x%zx .. end)\n\n",
                  static_cast<unsigned>(payload_size - kPlainHeader), kPlainHeader);
    t += buf;

    if (auto b = r.bytes(payload_off, 16)) t += "  +0x00  opaque     " + hex_of(*b) + "\n";
    if (auto b = r.bytes(payload_off + 0x10, 8)) t += "  +0x10  tag        " + hex_of(*b) + "\n";
    if (auto b = r.bytes(payload_off + 0x18, kNameField))
        t += "  +0x18  name       " + ascii_field(*b) + "\n";
    if (auto b = r.bytes(payload_off + 0x58, kNameField))
        t += "  +0x58  string     " + ascii_field(*b) + "\n";
    if (auto b = r.bytes(payload_off + 0x98, kNameField))
        t += "  +0x98  string     " + ascii_field(*b) + "\n";
    t += "  +0xd8  u32        " + u32_line(r, payload_off + 0xd8) + "\n";
    t += "  +0xdc  u32        " + u32_line(r, payload_off + 0xdc) + "  (unidentified)\n";
    if (auto b = r.bytes(payload_off + 0xe0, 8))
        t += "  +0xe0  component  " + ascii_field(*b) + "\n";
    t += "  +0xe8  u32        " + u32_line(r, payload_off + 0xe8) + "\n";

    std::vector<uint8_t> tb(t.begin(), t.end());
    if (root.write_file(subdir + "/sonicare_upg-info.txt", tb, 0644)) {
        out.files++;
        out.bytes += tb.size();
    }
}
}  // namespace

bool extract_sonicare_upg(const Reader& r, const Finding& f, SafeRoot& root,
                          const std::string& subdir, Extracted& out) {
    out.offset = f.offset;
    out.type = "sonicare_upg";
    out.root = subdir;

    auto header_length = r.at<uint16_t>(f.offset + 0x0E, Endian::Little);
    auto payload_size = r.at<uint32_t>(f.offset + 0x08, Endian::Little);
    if (!header_length || !payload_size) {
        out.status = "error:bad-header";
        return true;
    }

    const size_t header_off = f.offset;
    const size_t payload_off = f.offset + *header_length;
    const size_t trailer_off = payload_off + *payload_size;
    const size_t total = *header_length + static_cast<size_t>(*payload_size) + kTrailer;

    auto header = r.bytes(header_off, *header_length);
    auto payload = r.bytes(payload_off, *payload_size);
    auto trailer = r.bytes(trailer_off, kTrailer);
    if (!header || !payload || !trailer) {
        out.status = "error:truncated";
        return true;
    }

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    struct Piece {
        const char* name;
        std::span<const uint8_t> data;
    };
    const Piece pieces[] = {
        {"header.bin", *header},
        {"payload.bin", *payload},
        {"trailer.bin", *trailer},
    };
    for (const auto& p : pieces) {
        std::vector<uint8_t> data(p.data.begin(), p.data.end());
        if (!root.write_file(subdir + "/" + p.name, data, 0644)) {
            out.status = "error:write";
            return true;
        }
        out.files++;
        out.bytes += data.size();
    }

    write_info(r, payload_off, *payload_size, root, subdir, out);

    out.consumed = total;
    out.status = "ok";
    return true;
}

}  // namespace ft

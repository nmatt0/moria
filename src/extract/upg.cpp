// upg.cpp — ".upg" firmware container extraction. See upg.hpp.
//
// Re-reads payload_size (u32 LE @+0x08) and header_length (u16 LE @+0x0E)
// directly rather than trusting any pre-parsed fields, matching this codebase's
// other extractors. Writes header.bin / payload.bin / trailer.bin verbatim —
// no decoding, since the payload's internal encoding (past its short plaintext
// label) is unconfirmed.
#include "extract/upg.hpp"

#include <cstdint>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {
constexpr size_t kTrailer = 16;
}  // namespace

bool extract_upg(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.offset = f.offset;
    out.type = "upg";
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

    out.consumed = total;
    out.status = "ok";
    return true;
}

}  // namespace ft

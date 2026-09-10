// squashfs.cpp — SquashFS v4 refinement validator.
// The magic, layout, and structural constraints (version, block math, size)
// now live in signatures/squashfs.toml. This validator only does what the
// declarative layer can't: pick the compression name, format the version
// string, and raise confidence to `consistent` when the id-table pointer is
// internally sane (the same class of cross-field check binwalk/unblob apply).
#include "validators/squashfs.hpp"

#include <cstring>
#include <string>

namespace ft {

namespace {
constexpr uint64_t V4_HEADER_SIZE = 96;

const char* compression_name(uint64_t c) {
    switch (c) {
        case 1: return "gzip";
        case 2: return "lzma";
        case 3: return "lzo";
        case 4: return "xz";
        case 5: return "lz4";
        case 6: return "zstd";
        default: return nullptr;
    }
}

uint64_t field(const FieldMap& f, const char* k) {
    auto it = f.find(k);
    return it == f.end() ? 0 : it->second;
}
}  // namespace

bool validate_squashfs(ValidatorCtx& ctx) {
    const FieldMap& f = ctx.fields;

    ctx.out.version = std::to_string(field(f, "s_major")) + "." + std::to_string(field(f, "s_minor"));
    const uint64_t declared = field(f, "compression");
    if (const char* c = compression_name(declared))
        ctx.out.compression = c;
    else
        ctx.out.compression = "unknown(" + std::to_string(declared) + ")";

    // Flag vendor tampering that the superblock hides (cheap sniff, no decode).
    // Non-standard magic (TP-Link/Broadcom "shsq"/"hsqt") and a compression field
    // that lies about the block codec: LZMA1 blocks (props byte 0x5d) shipped with
    // the field left as gzip. The extractor auto-detects the real codec; here we
    // just make identify honest about it.
    const Reader& r = ctx.reader;
    // "hsqs" (LE) and "sqsh" (BE) are the two standard magics; anything else is a
    // vendor-modified magic (shsq/hsqt/qshs/tqsh/sqlz).
    if (auto m = r.bytes(ctx.offset, 4);
        m && std::memcmp(m->data(), "hsqs", 4) != 0 && std::memcmp(m->data(), "sqsh", 4) != 0)
        ctx.out.limitations.push_back(
            "non-standard starting bytes '" +
            std::string(reinterpret_cast<const char*>(m->data()), 4) +
            "' (SquashFS changed by the vendor)");
    if (!(field(f, "flags") & 0x0400)) {  // no compressor-options block -> first block is data
        if (auto b0 = r.bytes(ctx.offset + V4_HEADER_SIZE, 1)) {
            uint64_t sniff = (*b0)[0] == 0x5d ? 2 : ((*b0)[0] == 0x78 ? 1 : 0);
            if (sniff && sniff != declared) {
                const char* real = compression_name(sniff);
                const char* named = compression_name(declared);
                ctx.out.compression = std::string(real) + " (header says " +
                                      (named ? named : "?") + ")";
            }
        }
    }

    const uint64_t id_table = field(f, "id_table_start");
    const uint64_t bytes_used = field(f, "bytes_used");
    if (id_table >= V4_HEADER_SIZE && id_table <= bytes_used)
        ctx.out.set_confidence(Confidence::Consistent,
                               "version 4 header and ID table location are valid");
    else
        ctx.out.set_confidence(Confidence::Structural, "version 4 header values are valid");
    return true;
}

}  // namespace ft

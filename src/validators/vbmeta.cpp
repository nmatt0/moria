// vbmeta.cpp — AVB vbmeta refinement validator. See vbmeta.hpp.
#include "validators/vbmeta.hpp"

#include <cstdint>
#include <string>

namespace ft {

namespace {

uint64_t field(const FieldMap& f, const char* k) {
    auto it = f.find(k);
    return it == f.end() ? 0 : it->second;
}

const char* algo_name(uint64_t a) {
    switch (a) {
        case 0: return "NONE";
        case 1: return "SHA256_RSA2048";
        case 2: return "SHA256_RSA4096";
        case 3: return "SHA256_RSA8192";
        case 4: return "SHA512_RSA2048";
        case 5: return "SHA512_RSA4096";
        case 6: return "SHA512_RSA8192";
        default: return "unknown";
    }
}

// off + size stays within a block of `block_size` bytes (0/0 is fine: absent).
bool within(uint64_t off, uint64_t size, uint64_t block_size) {
    if (size == 0) return true;
    if (off > block_size) return false;
    return size <= block_size - off;
}

}  // namespace

bool validate_vbmeta(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    const uint64_t auth = field(ctx.fields, "auth_block_size");
    const uint64_t aux = field(ctx.fields, "aux_block_size");
    const uint64_t algo = field(ctx.fields, "algorithm_type");

    // Authentication-block members (hash, signature) live within `auth`.
    if (!within(field(ctx.fields, "hash_offset"), field(ctx.fields, "hash_size"), auth))
        return false;
    if (!within(field(ctx.fields, "signature_offset"), field(ctx.fields, "signature_size"), auth))
        return false;
    // Auxiliary-block members (public key, its metadata, descriptors) within `aux`.
    if (!within(field(ctx.fields, "public_key_offset"), field(ctx.fields, "public_key_size"), aux))
        return false;
    if (!within(field(ctx.fields, "public_key_metadata_offset"),
                field(ctx.fields, "public_key_metadata_size"), aux))
        return false;
    if (!within(field(ctx.fields, "descriptors_offset"), field(ctx.fields, "descriptors_size"),
                aux))
        return false;

    // release_string[48] at header offset 128 (after flags @120 and
    // rollback_index_location @124; reserved[80] follows at 176). NUL-terminated
    // ASCII, e.g. "avbtool 1.2.0". A neutral label; not an interpretation.
    std::string release;
    if (auto b = r.bytes(off + 128, 48)) {
        release.assign(reinterpret_cast<const char*>(b->data()), 48);
        if (auto z = release.find('\0'); z != std::string::npos) release.resize(z);
        // Keep only printable characters.
        for (char c : release)
            if (c && (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E)) {
                release.clear();
                break;
            }
    }
    ctx.out.label = release;
    ctx.out.version = std::string("AVB ") + std::to_string(field(ctx.fields, "avb_major")) + "." +
                      std::to_string(field(ctx.fields, "avb_minor"));

    std::string why = std::string("AVB vbmeta, algorithm ") + algo_name(algo);
    ctx.out.set_confidence(Confidence::Consistent, why);
    return true;
}

}  // namespace ft

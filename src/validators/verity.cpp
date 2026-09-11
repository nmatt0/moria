// verity.cpp — dm-verity superblock refinement validator.
//
// dm-verity stores a filesystem's integrity hash tree on a "hash device", which
// on firmware images is the region appended right after the protected
// filesystem (an Android system/vendor squashfs or erofs, typically). Its
// 512-byte superblock (Linux `verity_super_block`, all little-endian):
//   char     signature[8];   // "verity\0\0" (matched by the magic)
//   u32      version;        // 1
//   u32      hash_type;      // 0 (Chrome OS) or 1 (normal)
//   u8       uuid[16];
//   char     algorithm[32];  // "sha256", "sha1", ...
//   u32      data_block_size; // bytes per data block (protected fs)
//   u32      hash_block_size; // bytes per hash block (this device)
//   u64      data_blocks;     // number of data blocks covered
//   u16      salt_size;
//   ...salt, padding to 512...
//
// The hash tree is a fan-out tree over the data blocks: each hash block holds
// (hash_block_size / digest_size) child hashes, and levels stack until a single
// root block. We size the finding to the superblock block plus every tree
// level, so the metadata is labelled and owns its region instead of reading as
// unclaimed high-entropy space behind the filesystem. Any forward-error-
// correction (FEC) appended after the tree is device-specific and not derivable
// from the superblock, so it is deliberately not included (it stays a small
// unclaimed tail rather than a guessed over-claim).
#include "validators/verity.hpp"

#include <cstdint>
#include <string>

namespace ft {

namespace {

uint64_t field(const FieldMap& f, const char* k) {
    auto it = f.find(k);
    return it == f.end() ? 0 : it->second;
}

// Digest size in bytes for the algorithms dm-verity accepts. 0 = unknown.
uint32_t digest_size(const std::string& algo) {
    if (algo == "sha256" || algo == "sha512-256" || algo == "blake2b-256" ||
        algo == "blake2s-256")
        return 32;
    if (algo == "sha1") return 20;
    if (algo == "sha224") return 28;
    if (algo == "sha384") return 48;
    if (algo == "sha512" || algo == "blake2b-512") return 64;
    if (algo == "md5") return 16;
    if (algo == "ripemd160") return 20;
    return 0;
}

bool is_pow2(uint64_t v) { return v && (v & (v - 1)) == 0; }

}  // namespace

bool validate_verity(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    const uint64_t data_block_size = field(ctx.fields, "data_block_size");
    const uint64_t hash_block_size = field(ctx.fields, "hash_block_size");
    const uint64_t data_blocks = field(ctx.fields, "data_blocks");

    // Block sizes are always powers of two within a sane NAND/flash range; a
    // "verity\0\0" string in arbitrary data almost never satisfies this.
    if (!is_pow2(data_block_size) || data_block_size < 512 || data_block_size > 1u << 20)
        return false;
    if (!is_pow2(hash_block_size) || hash_block_size < 512 || hash_block_size > 1u << 20)
        return false;

    // algorithm[32] is a Bytes field (not in the FieldMap); read it directly.
    std::string algo;
    if (auto b = r.bytes(off + 32, 32)) {
        algo.assign(reinterpret_cast<const char*>(b->data()), 32);
        if (auto z = algo.find('\0'); z != std::string::npos) algo.resize(z);
    }
    ctx.out.label = algo;

    // Size = superblock block + every hash-tree level. digest_size 0 (unknown
    // algorithm) or a degenerate fan-out: label the superblock block only.
    const uint32_t ds = digest_size(algo);
    uint64_t total_blocks = 1;  // the superblock occupies the first hash block
    if (ds != 0) {
        const uint64_t per_block = hash_block_size / ds;
        if (per_block >= 2 && data_blocks > 0) {
            uint64_t blocks = data_blocks;
            while (blocks > 1) {
                blocks = (blocks + per_block - 1) / per_block;  // ceil
                total_blocks += blocks;
            }
        }
    }

    uint64_t size = total_blocks * hash_block_size;
    const uint64_t avail = r.size() - off;
    if (size > avail) size = avail;
    ctx.out.size = size;

    ctx.out.set_confidence(Confidence::Consistent, "dm-verity superblock fields consistent");
    return true;
}

}  // namespace ft

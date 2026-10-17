// sxverity.cpp — SpaceX "sxverity" dm-verity container (Starlink UT firmware). #55
//
// On-disk layout (per Quarkslab, "Diving into Starlink's User Terminal Firmware",
// and confirmed against two sample partitions):
//   0x000  "sxverity" magic, record 0
//   0x400  "sxverity" magic, record 1   } four 1024-byte records, byte-identical
//   0x800  "sxverity" magic, record 2   } in the images observed; each holds a
//   0xC00  "sxverity" magic, record 3   } verity root hash, a public key, and an
//                                         ed25519 signature over the record.
//   0x1000 "-rom1fs-"  big-endian romfs payload (volume name also "sxverity").
// We confirm the four records and the payload, then size the finding to the 4 KiB
// record table so the preamble is named and the romfs is reported on its own.
#include "validators/sxverity.hpp"

#include <cstdint>
#include <cstring>

namespace ft {

namespace {
constexpr size_t kRecord = 1024;                   // record stride
constexpr size_t kRecords = 4;                     // four records = the 4 KiB table
constexpr size_t kPreamble = kRecord * kRecords;   // 0x1000, payload starts here
constexpr uint8_t kMagic[8] = {'s', 'x', 'v', 'e', 'r', 'i', 't', 'y'};
constexpr uint8_t kRomfs[8] = {'-', 'r', 'o', 'm', '1', 'f', 's', '-'};

bool magic_at(const Reader& r, size_t off, const uint8_t (&m)[8]) {
    auto b = r.bytes(off, 8);
    return b && std::memcmp(b->data(), m, 8) == 0;
}
}  // namespace

bool validate_sxverity(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t base = ctx.offset;  // the matched magic (record 0)

    // Require the full four-record table and the romfs payload right after it.
    // This rejects a stray "sxverity" string that lacks the surrounding structure
    // (the romfs volume name is itself "sxverity", and the magic recurs at each
    // record boundary, so without this a single container yields spurious hits).
    for (size_t i = 0; i < kRecords; ++i)
        if (!magic_at(r, base + i * kRecord, kMagic)) return false;
    if (!magic_at(r, base + kPreamble, kRomfs)) return false;

    ctx.out.size = kPreamble;  // own the 4 KiB record table; romfs is its own finding
    ctx.out.set_confidence(Confidence::Consistent,
                           "sxverity: four-record signed table over a romfs payload");
    return true;
}

}  // namespace ft

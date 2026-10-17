#pragma once
#include "signature.hpp"
namespace ft {
// Confirm a SpaceX "sxverity" dm-verity container: four 1024-byte records whose
// magic "sxverity" starts each 0x400 boundary through 0xC00, followed by a
// big-endian romfs payload ("-rom1fs-") at 0x1000. Sizes the finding to the 4 KiB
// record table, so the preamble is named and the romfs payload surfaces as its
// own finding. Reaches `consistent` (magic + full record table + payload
// cross-check); rejects a stray "sxverity" string that lacks the structure (the
// romfs volume name is itself "sxverity"). See issue #55.
bool validate_sxverity(ValidatorCtx& ctx);
}  // namespace ft

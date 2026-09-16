// luks.hpp — LUKS1 / LUKS2 (dm-crypt) encrypted-volume identifier.
//
// Identify only: parse the on-disk header and report the parameters an operator
// needs to point key-recovery effort (version, cipher + mode, KDF, key size,
// UUID). The payload is encrypted and stays opaque — no decryption, no extractor.
#pragma once

#include "signature.hpp"

namespace ft {

// Magic "LUKS\xba\xbe" at offset 0. Branches on the version word: LUKS1 reads the
// fixed binary phdr; LUKS2 reads the binary header and extracts cipher/KDF/key
// size from the JSON metadata area. Rejects a LUKS2 secondary header
// (hdr_offset != 0). Reports at consistent tier (no header checksum is verified).
bool validate_luks(ValidatorCtx& ctx);

}  // namespace ft

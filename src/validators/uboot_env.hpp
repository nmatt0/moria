// uboot_env.hpp — U-Boot environment refinement validator.
//
// The environment has no format magic; the signature anchors on a NUL-prefixed
// common `key=value` assignment inside the block. This validator walks back from
// that anchor to the block header, walks the entry list to its empty-entry
// terminator, and recomputes the CRC32 over candidate env sizes to confirm the
// block (verified) and recover its exact extent. A clean key=value list whose
// CRC does not match any candidate size stays `structural`.
#pragma once

#include "signature.hpp"

namespace ft {

bool validate_uboot_env(ValidatorCtx& ctx);

}  // namespace ft

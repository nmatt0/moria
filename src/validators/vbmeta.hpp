// vbmeta.hpp — Android Verified Boot (AVB) vbmeta refinement validator.
//
// Confirms the authentication/auxiliary sub-block offsets are internally
// consistent (a stray "AVB0" in data will not satisfy them), reads the release
// string and algorithm for the label, and lifts a consistent match to the
// `consistent` tier. AVB carries no CRC, so `verified` is not reachable offline;
// signature verification (and the verification-posture interpretation) is
// mithril's job.
#pragma once

#include "signature.hpp"

namespace ft {

bool validate_vbmeta(ValidatorCtx& ctx);

}  // namespace ft

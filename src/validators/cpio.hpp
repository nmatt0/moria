#pragma once
#include "signature.hpp"

namespace ft {
// Validate a cpio header. For the "newc"/"crc" ASCII formats, verify the hex
// header fields and compute the entry size (so entries skip-ahead + coalesce
// into one archive region instead of one finding per member).
bool validate_cpio(ValidatorCtx& ctx);
}  // namespace ft

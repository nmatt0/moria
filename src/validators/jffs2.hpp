#pragma once
#include "signature.hpp"
namespace ft {
// Verify the JFFS2 node header CRC (crc32 no-invert over the first 8 bytes).
// Match -> `verified`; otherwise the declarative constraints still hold at `structural`.
bool validate_jffs2(ValidatorCtx& ctx);
}  // namespace ft

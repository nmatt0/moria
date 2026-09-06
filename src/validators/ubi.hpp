#pragma once
#include "signature.hpp"
namespace ft {
// Verify a UBI EC/VID header CRC (crc32 init 0xFFFFFFFF, no invert; stored BE @60
// over the first 60 bytes). Match -> `verified`.
bool validate_ubi(ValidatorCtx& ctx);
// Verify a UBIFS node CRC (same crc variant; stored LE @4 over node[8..len]).
bool validate_ubifs(ValidatorCtx& ctx);
}  // namespace ft

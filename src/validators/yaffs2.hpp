#pragma once
#include "signature.hpp"

namespace ft {
// YAFFS2 has no superblock magic. Heuristically recognize the first object
// header (little-endian): a valid object type, a plausible parent id, the
// deprecated 0xFFFF sum at offset 8, and a printable/empty name.
bool validate_yaffs2(ValidatorCtx& ctx);
}  // namespace ft

#pragma once
#include "signature.hpp"

namespace ft {
// Validate a suspected SquashFS superblock. See squashfs.cpp for the field map.
bool validate_squashfs(ValidatorCtx& ctx);
}  // namespace ft

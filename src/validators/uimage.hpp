#pragma once
#include "signature.hpp"

namespace ft {
// Validate a U-Boot legacy uImage header: verify the header CRC32, decode
// os/arch/type/compression/name. CRC match -> `verified`.
bool validate_uimage(ValidatorCtx& ctx);
}  // namespace ft

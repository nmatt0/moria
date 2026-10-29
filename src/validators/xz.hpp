// xz.hpp — xz stream-header CRC32 validator.
#pragma once

#include "signature.hpp"

namespace ft {

bool validate_xz(ValidatorCtx& ctx);

}  // namespace ft

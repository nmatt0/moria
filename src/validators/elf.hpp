#pragma once
#include "signature.hpp"

namespace ft {
// Decode an ELF header: class (32/64), endianness (EI_DATA), object type, and
// machine/arch. A recognized type + machine bumps confidence to `consistent`.
bool validate_elf(ValidatorCtx& ctx);
}  // namespace ft

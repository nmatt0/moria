#pragma once
#include "signature.hpp"

namespace ft {
// Validate that the file begins with a well-formed Intel HEX record (byte count,
// address, record type, hex data, and a correct checksum). Text format, so this
// is a whole-file check anchored at offset 0.
bool validate_ihex(ValidatorCtx& ctx);
}  // namespace ft

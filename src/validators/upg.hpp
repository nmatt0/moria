#pragma once
#include "signature.hpp"

namespace ft {
// Validate a ".upg" firmware container: confirm header_length + payload_size +
// 16 (trailer) matches the bytes available from the match offset, and pull the
// NUL-padded ASCII label found at payload offset 0x18 (after a 16-byte opaque
// prefix and a constant 8-byte tag). A derived size that lands exactly on EOF
// -> `verified`.
bool validate_upg(ValidatorCtx& ctx);
}  // namespace ft

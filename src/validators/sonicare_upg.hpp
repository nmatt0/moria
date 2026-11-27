#pragma once
#include "signature.hpp"

namespace ft {
// Validate a Philips Sonicare ".upg" firmware container: confirm
// header_length + payload_size + 16 (trailer) matches the bytes available,
// verify the constant 8-byte tag at payload offset 0x10, and pull the
// NUL-padded ASCII label at payload offset 0x18. Exact EOF span + tag match
// -> `verified`; either signal on its own -> `consistent`; neither ->
// `structural`.
bool validate_sonicare_upg(ValidatorCtx& ctx);
}  // namespace ft

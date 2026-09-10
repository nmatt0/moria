#pragma once
#include "signature.hpp"

namespace ft {
// Validate a RAE Systems / Honeywell RFP firmware package: confirm the "RAE"
// marker and the length-prefixed section table (IniFile/HexFile/BinFile/SIGN),
// walk it to derive the exact container size, the compression flag (any
// LZARI-compressed section), and the section count. A table that spans the file
// exactly -> `verified`.
bool validate_rae_rfp(ValidatorCtx& ctx);
}  // namespace ft

#pragma once
#include "signature.hpp"

namespace ft {
// Validate a VBF (Versatile Binary Format) firmware container: an ASCII
// `vbf_version = X.Y;` line, a brace-delimited `header { ... }` block, then a
// chain of binary blocks `[u32 be start][u32 be len][data][u16 be crc16]`. The
// validator matches the header braces, walks the block chain to the exact
// container span, reads data_format_identifier / sw_part_number for metadata,
// and verifies the per-block CRC16 on uncompressed blocks (-> verified).
bool validate_vbf(ValidatorCtx& ctx);
}  // namespace ft

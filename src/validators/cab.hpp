#pragma once
#include "signature.hpp"

namespace ft {
// Validate a Microsoft Cabinet: walk the folder and file tables (honouring the
// optional per-structure reserve widths), size the finding by cbCabinet, and
// report the folder compression codec. A cabinet whose declared size matches
// the bytes available is `verified`.
bool validate_cab(ValidatorCtx& ctx);
}  // namespace ft

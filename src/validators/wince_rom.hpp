#pragma once
#include "signature.hpp"

namespace ft {
// Validate a Windows CE XIP ROM image: resolve pTOC to a ROMHDR whose virtual
// base, physical span, and module/file table sizes agree with the file, then
// size the finding by the image span and label it with the module/file counts.
// A bootloader that carries a stale "ECEC" signature but no resolvable ROMHDR
// stays at `magic` tier so it is identified without driving an extraction.
bool validate_wince_rom(ValidatorCtx& ctx);
}  // namespace ft

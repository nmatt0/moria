#pragma once
#include "signature.hpp"

namespace ft {
// Validate a Windows CE registry hive: confirm the header shape around the
// "EKIM" signature and require that real value records are recoverable from the
// cell data. The record recovery is what separates a hive from four coincidental
// bytes, so it decides the tier.
bool validate_wince_hive(ValidatorCtx& ctx);
}  // namespace ft

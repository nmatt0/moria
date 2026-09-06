#pragma once
#include "signature.hpp"
namespace ft {
// Walk JPEG marker segments from SOI to EOI to compute the on-disk size.
// EOI found -> `consistent` + size; otherwise the marker constraint keeps it structural.
bool validate_jpeg(ValidatorCtx& ctx);
}  // namespace ft

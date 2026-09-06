// dtb.hpp — FDT/DTB refinement: reclassify a FIT (FDT with an /images node).
#pragma once

#include "signature.hpp"

namespace ft {
bool validate_dtb(ValidatorCtx& ctx);
}  // namespace ft

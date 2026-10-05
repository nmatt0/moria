#pragma once
#include "signature.hpp"

namespace ft {
// Validate an Artosyn OTRA firmware image: decode the header, recompute the
// SHA-256 over the body (0x220..EOF) and compare it to the stored digest
// (Verified on a match), and classify the body as segmented (lists partitions as
// members) or flat. See src/otra.hpp for the layout.
bool validate_otra(ValidatorCtx& ctx);
}  // namespace ft

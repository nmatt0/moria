// android_boot.hpp — size refinement for Android boot images.
#pragma once

#include "signature.hpp"

namespace ft {

// Compute the true total image span (header page + each page-padded component)
// from the boot header, so the `android_boot` finding covers the whole image
// rather than defaulting to the tiny struct/inferred size. That lets the
// interior kernel/ramdisk (and any spurious magic hits inside them) be treated
// as region interior, and stops the components leaking as separate top-level
// findings. Always a valid match — this only sets the size.
bool validate_android_boot(ValidatorCtx& ctx);

}  // namespace ft

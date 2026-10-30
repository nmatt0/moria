// mtk_lk.hpp — MediaTek LK (Little Kernel) bootloader image validation.
#pragma once

#include "signature.hpp"

namespace ft {

// Confirm a MediaTek LK image past the 0x58881688 magic: require a printable
// partition name at offset 8 (the false-positive gate against a coincidental
// 4-byte magic over binary data), record it as the finding label, and span the
// region to the declared payload size when it fits the file (Consistent tier).
// A stray magic with a non-printable name is rejected.
bool validate_mtk_lk(ValidatorCtx& ctx);

}  // namespace ft

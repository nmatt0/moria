// deobf.hpp — identify-time refinement for recognized vendor-encrypted formats.
#pragma once

#include "signature.hpp"

namespace ft {

// A vendor-descramble signature matched its header magic. Cheaply probe (a
// first-block decrypt, read-only, no disk) whether we hold a working key: if so,
// upgrade to verified ("encrypted; decryptable ...") and size the finding to the
// whole header+ciphertext span; otherwise keep it structural ("encrypted; key
// not confirmed"). Always a valid match — this only refines confidence/size.
bool validate_deobf(ValidatorCtx& ctx);

}  // namespace ft

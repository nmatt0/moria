#pragma once
#include "signature.hpp"

namespace ft {
// Validate a compound file (CFBF): build the FAT from the DIFAT, walk the
// directory, and size the finding by the last sector the FAT accounts for.
// Names the flavour (MSI when the stream names use MSI's encoding) and counts
// storages/streams. A compound file whose span fits the bytes available and
// whose directory parses is `verified`.
bool validate_cfbf(ValidatorCtx& ctx);
}  // namespace ft

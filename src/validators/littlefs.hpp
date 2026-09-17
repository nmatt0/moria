// littlefs.hpp — LittleFS identification validator.
#pragma once

#include "signature.hpp"

namespace ft {

// Anchored on the "littlefs" magic at superblock offset 8. Parses the superblock
// metadata pair, verifies the commit CRC, and reports version + geometry. Sizes
// the finding to the whole filesystem (block_size * block_count).
bool validate_littlefs(ValidatorCtx& ctx);

}  // namespace ft

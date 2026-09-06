#pragma once
#include "signature.hpp"
namespace ft {
// Walk POSIX ustar member headers from the archive start to the end-of-archive
// zero block, validating each header's octal checksum and summing member sizes to
// compute the whole-archive span. This makes the archive one finding (so interior
// member headers are suppressed instead of each re-extracting the tail) and the
// checksum check rejects stray "ustar" bytes in binary data. No valid header ->
// reject.
bool validate_tar(ValidatorCtx& ctx);
}  // namespace ft

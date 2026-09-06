#pragma once
#include "signature.hpp"
namespace ft {
// Locate the End-Of-Central-Directory record, validate the central directory
// bounds, and compute the archive size -> `consistent` + size. Distinguishes a
// real ZIP from a stray "PK\x03\x04".
bool validate_zip(ValidatorCtx& ctx);
}  // namespace ft

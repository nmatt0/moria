// registry.hpp — resolve a validator name (from a TOML signature) to a function.
#pragma once

#include <string>

#include "signature.hpp"

namespace ft {
// Returns nullptr if no validator is registered under `name`.
Validator find_validator(const std::string& name);
}  // namespace ft

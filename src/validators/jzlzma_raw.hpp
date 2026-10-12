// jzlzma_raw.hpp — validator for the raw (unwrapped) Ingenic jzlzma stream.
#pragma once

#include "../signature.hpp"

namespace ft {

bool validate_jzlzma_raw(ValidatorCtx& ctx);

}  // namespace ft

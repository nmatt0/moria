// esp32_part.hpp — ESP-IDF partition table validator (issue #18).
#pragma once

#include "signature.hpp"

namespace ft {

bool validate_esp32_partition_table(ValidatorCtx& ctx);

}  // namespace ft

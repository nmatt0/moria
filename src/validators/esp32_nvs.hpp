// esp32_nvs.hpp — ESP-IDF NVS validator (issue #18).
#pragma once

#include "signature.hpp"

namespace ft {

bool validate_esp32_nvs(ValidatorCtx& ctx);

}  // namespace ft

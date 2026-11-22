#pragma once
#include "signature.hpp"

namespace ft {
// Validate a VFW firmware container: 16-byte header (8-byte ASCII magic,
// u32 LE payload_size, u32 LE CRC-32 over payload). Checks payload_size
// against available bytes, verifies the CRC-32 -> verified if it matches,
// consistent if the size spans to EOF but CRC mismatches, structural
// otherwise. Extracts the component class (MCU/BLE/GPS/WFS) into the label.
bool validate_vfw(ValidatorCtx& ctx);
}  // namespace ft

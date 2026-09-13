// uefi_fv.hpp — UEFI Firmware Volume refinement validator.
//
// Confirms the 16-bit header checksum (sum of the header's UINT16 words == 0),
// which rejects a stray "_FVH" in arbitrary data and lifts a real volume to the
// verified tier, and labels the volume by its filesystem GUID (notably the
// EfiSystemNvData GUID, which marks the NVRAM variable store).
#pragma once

#include "signature.hpp"

namespace ft {

bool validate_uefi_fv(ValidatorCtx& ctx);

}  // namespace ft

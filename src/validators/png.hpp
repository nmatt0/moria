#pragma once
#include "signature.hpp"
namespace ft {
// Compute a PNG's true on-disk size by walking its chunk list from the IHDR
// (just past the 8-byte signature) to IEND, instead of letting the finding run
// to the next finding or EOF. Each chunk's CRC-32 is checked: a full walk with
// every CRC valid promotes the finding to `verified`, a walk that reaches IEND
// without full CRC coverage stays `consistent`. Never rejects — the 16-byte
// signature+IHDR magic is already decisive, so a truncated image keeps its
// finding with size left for inference. See issue #58.
bool validate_png(ValidatorCtx& ctx);
}  // namespace ft

#pragma once
#include "signature.hpp"
namespace ft {
// Compute a GIF's true on-disk size by walking its block stream (logical screen
// descriptor, optional global color table, then image-descriptor / extension
// blocks and their sub-block chains) to the 0x3B trailer, instead of letting the
// finding run to the next finding or EOF. A full walk to the trailer promotes the
// finding to `consistent` (GIF has no checksum to reach `verified`). The 6-byte
// GIF8[79]a magic is weak, so the validator also rejects clear false positives:
// after the header + global color table a real GIF must begin with a block
// introducer (0x2C / 0x21 / 0x3B), and anything else is not a GIF. A truncated
// but real GIF keeps a valid first introducer, so it survives with its size left
// for inference. See issue #58.
bool validate_gif(ValidatorCtx& ctx);
}  // namespace ft

// jzlzma.hpp — Ingenic jzlzma identifier.
#pragma once
#include "signature.hpp"
namespace ft {
// The mark_rootfs_lzma wrapper (magic 0x27051956 little-endian at +4) declares
// its payload, dictionary and uncompressed sizes. This re-checks those fields
// and trial-decodes the declared payload to exactly the declared uncompressed
// size, so a stray magic with plausible fields cannot false-positive. Reports
// `verified` and claims the exact 16 + payload_size span.
bool validate_jzlzma(ValidatorCtx& ctx);
}  // namespace ft

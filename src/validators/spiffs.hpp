// spiffs.hpp — SPIFFS identification validator.
#pragma once
#include "signature.hpp"
namespace ft {
// Anchored on a committed object-index header (flags 0xF8). Infers the geometry
// over the image and confirms a coherent object graph; reports at offset 0.
bool validate_spiffs(ValidatorCtx& ctx);
}  // namespace ft

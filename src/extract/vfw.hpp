// vfw.hpp — VFW firmware container extractor.
//
// Strips the 16-byte header and writes the raw payload as a single file named
// for the component class and variant (e.g. "MCU_F1.bin"). The payload is an
// opaque firmware binary — MCU payloads are typically ARM Cortex-M (vector
// table at byte 0); BLE/GPS/WFS payloads are vendor-specific blobs. moria's
// recursive identification handles whatever the payload turns out to contain.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_vfw(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

}  // namespace ft

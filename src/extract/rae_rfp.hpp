// rae_rfp.hpp — RAE Systems / Honeywell RFP section extractor.
//
// Walks the RFP section table (IniFile/HexFile/BinFile/SIGN, with _1 variants on
// multi-image devices) and writes one file per section under the output subdir.
// Stored sections are copied verbatim; LZARI-compressed sections are decoded via
// lzari_decompress(), so the underlying Intel-HEX and raw binary images become
// directly available (and are re-identified when moria recurses into them).
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_rae_rfp(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                     Extracted& out);

}  // namespace ft

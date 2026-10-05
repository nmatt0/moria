// wince_rom.hpp — Windows CE XIP ROM extractor.
//
// Produces two trees under the output subdir:
//
//   modules/  one file per TOCentry. XIP modules are not stored as PE files —
//             romimage splits each into an E32 ROM header, an O32 section
//             table, and the section bytes scattered through the image — so
//             each is rebuilt into a flat PE (file offset == RVA) that a
//             disassembler or a PE parser can open directly.
//   files/    one file per FILESentry, CECompress-decoded where needed.
//
// Everything here is what makes a .cos worth opening: the registry hives, the
// .CAB installers, the certificates and the vendor DLLs all live in files/,
// and moria's normal recursion then descends into them.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_wince_rom(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                       Extracted& out);

}  // namespace ft

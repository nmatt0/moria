// wince_hive.hpp — Windows CE registry hive value dump.
//
// The hive itself is already a file; what extraction adds is readability. CE's
// registry is where a device keeps its service configuration, its account and
// key material, and its certificates, all encoded as UTF-16 cell records that
// no text search will find. This writes every recoverable value out as one line
// of text — offset, name, type, value — so the rest of the toolchain (and a
// person with grep) can read it.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_wince_hive(const Reader& r, const Finding& f, SafeRoot& root,
                        const std::string& subdir, Extracted& out);

}  // namespace ft

// descramble.hpp — extraction seam for vendor-descrambled/encrypted payloads.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "extract/safepath.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

// Undo a recognized vendor scrambling method, write the checked result as
// `descrambled.bin`, and let moria identify and unpack it. A warning records the
// method, key description, and recognized file type. The encrypted bytes remain
// in the input; `-c` can copy that exact section.
bool extract_descramble(const Reader& r, const Finding& f, SafeRoot& root,
                        const std::string& subdir, Extracted& out);

}  // namespace ft

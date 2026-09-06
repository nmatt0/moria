// descramble.hpp — extraction seam for vendor-descrambled/encrypted payloads.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "extract/safepath.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

// Reverse a recognized vendor transform (the finding's `type` names the scheme),
// write the validated plaintext as `descrambled.bin`, and let the extraction
// recursion identify + unpack it. The scheme + key + validated magic are recorded
// as a manifest warning for provenance. The encrypted bytes are not copied here
// (the input holds them; `-c` carves the exact range).
bool extract_descramble(const Reader& r, const Finding& f, SafeRoot& root,
                        const std::string& subdir, Extracted& out);

}  // namespace ft

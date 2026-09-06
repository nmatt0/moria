// scan.hpp — whole-buffer signature scan.
// M0: literal multi-magic scan with first-byte prefilter + inline skip-ahead.
// M2 replaces the scan with Aho-Corasick and adds the deterministic 3-pass
// conflict resolver; the signature/validator interface stays the same.
#pragma once

#include <vector>

#include "finding.hpp"
#include "reader.hpp"
#include "signature.hpp"

namespace ft {

std::vector<Finding> scan(const Reader& reader, const std::vector<Signature>& sigs);

}  // namespace ft

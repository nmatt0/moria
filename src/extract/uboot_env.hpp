// uboot_env.hpp — U-Boot environment extractor.
//
// Decodes the NUL-separated key=value list of an identified env block into a
// single `uboot-env.txt` (one `key=value` per line). Interpretation of the
// variables (credentials, network config, boot args) is mithril's job; moria
// only turns the block into a readable, re-parseable artifact.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_uboot_env(const Reader& r, const Finding& f, SafeRoot& root,
                       const std::string& subdir, Extracted& out);

}  // namespace ft

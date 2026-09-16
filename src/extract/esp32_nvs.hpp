// esp32_nvs.hpp — ESP-IDF NVS extractor (issue #18).
//
// Decodes an identified NVS region into a single `nvs-values.txt`: one
// `namespace:key = value ; type` line per live key, with a header comment
// carrying page/namespace/key counts and the list of credential-looking keys.
// Interpretation of the values belongs to mithril; moria only turns the page
// log into a readable, re-parseable artifact.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_esp32_nvs(const Reader& r, const Finding& f, SafeRoot& root,
                       const std::string& subdir, Extracted& out);

}  // namespace ft

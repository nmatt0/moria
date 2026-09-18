// spiffs.hpp — SPIFFS extraction entry point.
#pragma once
#include "extract/manifest.hpp"
namespace ft {
bool extract_spiffs(const Reader& r, const Finding& f, SafeRoot& root,
                    const std::string& subdir, Extracted& out);
}  // namespace ft

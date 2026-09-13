// vbmeta.hpp — AVB vbmeta artifact extractor.
//
// Writes the two auxiliary-block artifacts a downstream analyzer wants: the
// signing public key (vbmeta-pubkey.bin) and the raw descriptors block
// (vbmeta-descriptors.bin). Parsing the descriptors and matching the key against
// known/test keys is mithril's job; moria just carves the bytes out.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_vbmeta(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out);

}  // namespace ft

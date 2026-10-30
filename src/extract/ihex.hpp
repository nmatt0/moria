// ihex.hpp — Intel HEX image decoder.
//
// An Intel HEX file is line-oriented ASCII that *programs* a flat binary: each
// record carries an address and data bytes. moria identifies the format but,
// until this extractor, never materialized the binary it describes, so the back
// half of the pipeline (mithril, and moria's own recursion) only ever saw hex
// text. This extractor reassembles the programmed bytes into the flat image(s)
// and writes them out so they get scanned like any other extracted blob.
#pragma once

#include "extract/manifest.hpp"

namespace ft {

// Decode the Intel HEX stream at `f.offset` into one output file per contiguous
// programmed address range. Returns true (the extractor contract); a stream that
// is not standard Intel HEX yields status "partial" with no files rather than a
// hard failure.
bool extract_ihex(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out);

}  // namespace ft

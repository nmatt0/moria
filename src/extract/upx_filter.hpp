// upx_filter.hpp — reverse UPX's executable-code filters ("un-filter").
//
// Before compressing an executable segment, UPX rewrites the operands of
// relative branches so they compress better (a "calltrick"): the relative
// displacement is turned into an absolute-ish value, optionally tagged with a
// "cto" marker byte. To recover the original bytes, the displacement must be
// turned back after decompression. Each b_info block records the filter id
// (b_ftid) and cto parameter (b_cto8); an id of 0 means the block was not
// filtered.
//
// Reimplemented from the published UPX filter algorithms; validated
// byte-for-byte against `upx -d` output. Only the filters that occur in real ELF firmware are
// implemented (x86 call/jmp/jcc calltricks and ARM/ARM64 branch calltricks);
// upx_unfilter reports false for any id it does not implement, so the caller can
// mark the extraction partial rather than emit wrong bytes.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace ft {

// True if upx_unfilter implements filter id `ftid` (0 = "no filter", always true).
bool upx_filter_supported(uint8_t ftid);

// Reverse filter `ftid` (with cto byte `cto`) in place over `buf`. Returns false
// for an unimplemented filter id (buf left unchanged); true otherwise, including
// ftid == 0 (nothing to do).
bool upx_unfilter(std::span<uint8_t> buf, uint8_t ftid, uint8_t cto);

}  // namespace ft

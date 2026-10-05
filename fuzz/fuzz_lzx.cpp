// fuzz_lzx.cpp — libFuzzer entry point for the LZX decompressors.
//
// The CE-ROM (CECompress) and MS-CAB framings both drive the same Huffman/match
// decoder from lengths and offsets taken straight out of the input, so they are
// the sharpest edge in the Windows CE / cabinet path. Both entry points are fed
// directly here — a declared output length is taken from the fuzzer bytes too,
// so the "header claims a huge decode" case is covered — and the same bytes go
// through the full scan+identify pipeline so the .cos / .cab validators see
// adversarial input as well.
//
// Build via fuzz/build.sh. Run: ./fuzz_lzx -max_total_time=60
#include <cstddef>
#include <cstdint>
#include <span>

#include "extract/lzx.hpp"
#include "reader.hpp"
#include "scan.hpp"
#include "sigload.hpp"

#ifndef FT_FUZZ_SIGDIR
#define FT_FUZZ_SIGDIR "signatures"
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const ft::LoadResult sigs = ft::load_signatures(FT_FUZZ_SIGDIR);
    if (size < 4) return 0;

    // First three bytes pick the declared output length (capped so the fuzzer
    // spends its time on the decoder, not on allocating) and the LZX window.
    const size_t out_len = 1 + ((size_t(data[0]) << 8 | data[1]) & 0x3FFFF);
    const unsigned window = 15 + (data[2] % 8);  // includes the invalid 22
    std::span<const uint8_t> body(data + 3, size - 3);

    auto ce = ft::ce_decompress_rom(body, out_len);
    (void)ce;
    auto cab = ft::lzx_decompress_cab(body, out_len, window);
    (void)cab;

    ft::Reader reader(std::span<const uint8_t>(data, size));
    auto findings = ft::scan(reader, sigs.signatures);
    (void)findings;
    return 0;
}

// fuzz_nilfs2.cpp — libFuzzer entry point for the NILFS2 extractor.
// Feeds fuzzer bytes to the parse-only read chain (superblock selection, super
// root, DAT translation, cpfile, ifile, directory walk, block maps) with a
// partition at offset 0, and to the full scan pipeline so the identify/validator
// path also sees adversarial input (issue #64).
//
// Build via fuzz/build.sh. Run: ./fuzz_nilfs2 -max_total_time=60
#include <cstddef>
#include <cstdint>
#include <span>

#include "extract/nilfs2.hpp"
#include "reader.hpp"
#include "scan.hpp"
#include "sigload.hpp"

#ifndef FT_FUZZ_SIGDIR
#define FT_FUZZ_SIGDIR "signatures"
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const ft::LoadResult sigs = ft::load_signatures(FT_FUZZ_SIGDIR);
    ft::Reader reader(std::span<const uint8_t>(data, size));

    // Direct: the whole read chain with the filesystem at offset 0.
    ft::nilfs2_probe(reader, 0);

    // Via the pipeline: magic-driven identification on the raw bytes.
    auto findings = ft::scan(reader, sigs.signatures);
    (void)findings;
    return 0;
}

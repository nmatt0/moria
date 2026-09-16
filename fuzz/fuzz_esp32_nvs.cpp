// fuzz_esp32_nvs.cpp — libFuzzer entry point for the ESP-IDF NVS parser.
// Feeds fuzzer bytes to the NVS page walk/decode directly (a partition at
// offset 0) and to the full scan pipeline (page-state magic at arbitrary
// offsets), covering identification and the extraction decode on adversarial
// input (issue #18).
//
// Build via fuzz/build.sh. Run: ./fuzz_esp32_nvs -max_total_time=60
#include <cstddef>
#include <cstdint>
#include <span>

#include "esp32_nvs_parse.hpp"
#include "reader.hpp"
#include "scan.hpp"
#include "sigload.hpp"

#ifndef FT_FUZZ_SIGDIR
#define FT_FUZZ_SIGDIR "signatures"
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const ft::LoadResult sigs = ft::load_signatures(FT_FUZZ_SIGDIR);
    ft::Reader reader(std::span<const uint8_t>(data, size));

    // Direct: full page walk + value decode with a partition at offset 0.
    ft::NvsParse p = ft::nvs_parse(reader, 0);
    (void)p;

    // Via the pipeline: page-state-magic-driven validation anywhere.
    auto findings = ft::scan(reader, sigs.signatures);
    (void)findings;
    return 0;
}

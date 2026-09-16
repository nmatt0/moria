// fuzz_esp32_part.cpp — libFuzzer entry point for the ESP-IDF partition table.
// Feeds fuzzer bytes to the table validator directly (as if the table sat at
// offset 0) and to the full scan pipeline, so both the focused parser and the
// signature/validator path see adversarial input (issue #18).
//
// Build via fuzz/build.sh. Run: ./fuzz_esp32_part -max_total_time=60
#include <cstddef>
#include <cstdint>
#include <span>

#include "layout.hpp"
#include "reader.hpp"
#include "scan.hpp"
#include "sigload.hpp"
#include "signature.hpp"
#include "validators/esp32_part.hpp"

#ifndef FT_FUZZ_SIGDIR
#define FT_FUZZ_SIGDIR "signatures"
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const ft::LoadResult sigs = ft::load_signatures(FT_FUZZ_SIGDIR);
    ft::Reader reader(std::span<const uint8_t>(data, size));

    // Direct: the table at offset 0 (alignment guard passes).
    ft::Finding f;
    ft::FieldMap fields;
    ft::ValidatorCtx ctx{reader, 0, ft::Endian::Little, fields, f};
    ft::validate_esp32_partition_table(ctx);

    // Via the pipeline: magic-driven placement anywhere in the image.
    auto findings = ft::scan(reader, sigs.signatures);
    (void)findings;
    return 0;
}

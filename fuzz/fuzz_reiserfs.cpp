// fuzz_reiserfs.cpp — libFuzzer entry point for the ReiserFS extractor.
// Drives the parse-only tree/leaf-item walk directly: the fuzzer bytes are the
// tree region, spliced after a fixed valid superblock so the walk is always
// reached, with the superblock tried at both the 3.6 (64 KiB) and 3.5 (8 KiB)
// placements. Also feeds the raw bytes to the full scan pipeline so the
// identify/validator path sees adversarial input (issue #63).
//
// Build via fuzz/build.sh. Run: ./fuzz_reiserfs -max_total_time=60
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "extract/reiserfs.hpp"
#include "reader.hpp"
#include "scan.hpp"
#include "sigload.hpp"

#ifndef FT_FUZZ_SIGDIR
#define FT_FUZZ_SIGDIR "signatures"
#endif

namespace {
constexpr uint64_t BS = 4096;
constexpr uint64_t SB_BLK = 16;  // 64 KiB / 4096

// A minimal valid superblock so locate_base/root_block_ok accept block SB_BLK+1
// as the tree root; the fuzzer owns everything from the root block onward.
void write_sb(std::vector<uint8_t>& img, uint32_t nblocks, uint32_t root_block,
              const char* magic) {
    const size_t o = SB_BLK * BS;
    auto put32 = [&](size_t off, uint32_t v) { std::memcpy(img.data() + o + off, &v, 4); };
    auto put16 = [&](size_t off, uint16_t v) { std::memcpy(img.data() + o + off, &v, 2); };
    put32(0, nblocks);        // s_block_count
    put32(8, root_block);     // s_root_block
    put16(44, BS);            // s_blocksize
    std::memcpy(img.data() + o + 52, magic, std::strlen(magic));  // s_magic
    put16(68, 3);             // s_tree_height
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const ft::LoadResult sigs = ft::load_signatures(FT_FUZZ_SIGDIR);

    // Build an image: [zeros .. SB block .. fuzzer bytes as the tree region].
    // Cap so a pathological size field can't make us allocate unboundedly here.
    const size_t tree_bytes = size > (8u << 20) ? (8u << 20) : size;
    const uint32_t nblocks = static_cast<uint32_t>((SB_BLK + 1) + (tree_bytes + BS - 1) / BS + 1);
    std::vector<uint8_t> img(static_cast<size_t>(nblocks) * BS, 0);
    const uint32_t root_block = SB_BLK + 1;
    std::memcpy(img.data() + static_cast<size_t>(root_block) * BS, data, tree_bytes);

    for (const char* magic : {"ReIsEr2Fs", "ReIsErFs"}) {
        write_sb(img, nblocks, root_block, magic);
        ft::Reader reader(std::span<const uint8_t>(img.data(), img.size()));
        ft::reiserfs_probe(reader, SB_BLK * BS);
    }

    // Via the pipeline: magic-driven identification on the raw bytes.
    ft::Reader raw(std::span<const uint8_t>(data, size));
    auto findings = ft::scan(raw, sigs.signatures);
    (void)findings;
    return 0;
}

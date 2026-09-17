// littlefs.hpp — LittleFS on-disk parser shared by the validator + extractor.
//
// LittleFS is a power-fail-safe flash filesystem (the default on-flash store on
// Zephyr / Mbed / ESP-IDF / nRF / STM32 MCU firmware). Metadata lives in
// "metadata pairs" (two alternating blocks, each a log of CRC-checked commits of
// XOR-chained tags); file data is stored inline or via a CTZ skip-list. Geometry
// (block_size / block_count) is self-contained in the superblock, so no external
// geometry is needed. Format verified byte-exact against real mklittlefs images
// (see docs/littlefs-ondisk-notes.md). littlefs is BSD-3-Clause: the CTZ/commit
// algorithm was reimplemented clean against moria's Reader (see THIRD_PARTY.md).
#pragma once

#include <cstdint>
#include <string>

#include "reader.hpp"

namespace ft {

class SafeRoot;

struct LfsSuper {
    bool ok = false;
    bool crc_verified = false;  // the superblock metadata-pair CRC checked out
    uint32_t version = 0;       // (major<<16)|minor, e.g. 0x00020001 = v2.1
    uint32_t block_size = 0;
    uint32_t block_count = 0;
    uint32_t name_max = 0;
    uint32_t file_max = 0;
    uint32_t attr_max = 0;
    size_t origin = 0;         // byte offset of block 0 (the fs start) in the reader
};

// Parse the superblock metadata pair (block 0/1) at byte offset `origin`: find the
// "littlefs" magic + inline-struct geometry and verify the commit CRC. Returns
// ok=false when there is no valid littlefs superblock at `origin`.
LfsSuper lfs_read_super(const Reader& r, size_t origin = 0);

// Extraction stats.
struct LfsStats {
    size_t files = 0;
    size_t dirs = 0;
    size_t bytes = 0;
    bool truncated = false;   // a guard (depth/count/size) stopped the walk
    bool crc_fail = false;    // at least one mdir failed CRC during the walk
};

// Walk the whole filesystem from the superblock and write every regular file to
// `root` under `subdir`, recreating the directory tree. Honors SafeRoot's path
// safety and the caps below. Returns false only on a hard failure.
bool lfs_extract(const Reader& r, const LfsSuper& s, SafeRoot& root,
                 const std::string& subdir, LfsStats& st);

}  // namespace ft

// spiffs_parse.hpp — SPIFFS on-disk parser shared by the validator + extractor.
//
// SPIFFS is the classic SPI-NOR flash filesystem on ESP8266 / ESP32-classic and
// other small MCUs. It has no superblock magic and its geometry (page/block size)
// is build-time config NOT stored in the image, so it is inferred. Objects are a
// flat store: an object-index header page (name + size) plus data pages tagged by
// span index. Verified byte-exact against real mkspiffs images
// (docs/spiffs-ondisk-notes.md). Identify/extract only; no CRC in SPIFFS.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "reader.hpp"

namespace ft {

class SafeRoot;

struct SpiffsGeom {
    bool ok = false;
    uint32_t page_size = 0;
    uint32_t block_size = 0;
    size_t files = 0;          // objects with a FINAL index header
    size_t complete = 0;       // files whose data fully reassembled
    uint64_t total_bytes = 0;  // sum of recovered file sizes
};

// Infer the SPIFFS geometry over [0, r.size()) by trying candidate page/block
// sizes and scoring the recovered object graph. ok=false when nothing consistent.
SpiffsGeom spiffs_infer(const Reader& r);

struct SpiffsStats {
    size_t files = 0;
    size_t bytes = 0;
    bool truncated = false;
};

// Extract every object under the inferred geometry into `root`/`subdir`.
bool spiffs_extract(const Reader& r, const SpiffsGeom& g, SafeRoot& root,
                    const std::string& subdir, SpiffsStats& st);

}  // namespace ft

// carve.hpp — raw byte-range carving (the `-c` mode), distinct from extract.
//
// Extract (`-e`) parses a filesystem/container and reconstructs its files.
// Carve dumps the raw byte range of each finding (and the unidentified regions
// between them) to disk as standalone blobs, WITHOUT parsing — so a researcher
// still gets the bytes when extraction fails (vendor-obfuscated squashfs, an
// unsupported/corrupt variant) to hand to another tool or inspect by hand.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "finding.hpp"
#include "reader.hpp"

namespace ft {

struct CarveResult {
    size_t regions_written = 0;   // .bin files written
    uint64_t bytes_written = 0;   // total raw bytes carved
    size_t skipped_unknown = 0;   // findings with unknown (0) size, not carvable
    bool capped = false;          // hit the max-bytes cap
    std::string outdir;           // where the blobs landed
};

// Carve `findings` (each with a known size) plus the unidentified gaps between
// them into `outdir` as `<offset>-<type>.bin` / `<offset>-unknown.bin`. When
// `all` is false, small unidentified gaps (< 1 KiB, typically padding) are not
// carved; `all` carves every gap. Total carved bytes are capped at `max_bytes`.
CarveResult carve(const std::string& src_path, const Reader& reader,
                  const std::vector<Finding>& findings, const std::string& outdir, bool all,
                  uint64_t max_bytes);

}  // namespace ft

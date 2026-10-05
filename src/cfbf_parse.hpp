// cfbf_parse.hpp — Compound File Binary Format (CFBF) structure walking.
//
// A compound file is a FAT filesystem in miniature: a 512-byte header, then
// sectors chained through a file allocation table, holding a directory tree of
// storages (directories) and streams (files). MSI installers, .doc/.xls, and
// Outlook .msg are all this format.
//
// This is [MS-CFB] and nothing above it. The COM layer that the format was
// originally built for (structured storage: class-bound objects, \001CompObj,
// property sets) is not parsed or interpreted here — a stream is bytes.
//
// Why moria needs it: a stream is NOT contiguous on disk. An installer's
// Data1.cab lives in a compound-file stream, so a linear scan finds the MSCF
// magic at the stream's first sector and then reads whatever sectors happen to
// follow — usually a few kilobytes in, that is some other stream's bytes. The
// cabinet decodes perfectly right up to the first sector jump and turns to
// noise after it. Reassembling the chain first is the only way to read it.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "reader.hpp"

namespace ft {

// FAT entry markers. Anything <= kCfbfMaxSect is a real sector number.
constexpr uint32_t kCfbfMaxSect = 0xFFFFFFFA;
constexpr uint32_t kCfbfDifSect = 0xFFFFFFFC;
constexpr uint32_t kCfbfFatSect = 0xFFFFFFFD;
constexpr uint32_t kCfbfEndChain = 0xFFFFFFFE;
constexpr uint32_t kCfbfFree = 0xFFFFFFFF;

constexpr uint32_t kCfbfNoStream = 0xFFFFFFFF;

constexpr uint8_t kCfbfStorage = 1;
constexpr uint8_t kCfbfStream = 2;
constexpr uint8_t kCfbfRoot = 5;

struct CfbfEntry {
    std::string name;   // display name: MSI-demangled when it was encoded
    uint8_t type = 0;   // kCfbfStorage | kCfbfStream | kCfbfRoot
    uint32_t start = 0; // first sector (mini-FAT sector when size < mini_cutoff)
    uint64_t size = 0;
    bool mangled = false;  // the stored name used MSI's code-unit encoding
    // Directory tree links: siblings form a red-black tree per storage, `child`
    // heads the tree of whatever a storage contains. kCfbfNoStream = absent.
    uint32_t left = 0xFFFFFFFF, right = 0xFFFFFFFF, child = 0xFFFFFFFF;
};

struct Cfbf {
    unsigned sector_size = 512;
    unsigned mini_sector_size = 64;
    uint32_t mini_cutoff = 4096;
    uint16_t ver_major = 3;
    uint16_t ver_minor = 0;
    std::vector<uint32_t> fat;
    std::vector<uint32_t> minifat;
    std::vector<CfbfEntry> entries;  // directory order, root first when present
    uint32_t mini_start = 0;         // root entry's chain: the mini-stream container
    uint64_t mini_size = 0;
    uint64_t span = 0;               // bytes the compound file occupies from `base`
    size_t streams = 0;
    size_t storages = 0;
    bool msi = false;                // at least one MSI-encoded name
};

// Parse header, FAT, mini-FAT and directory at `base`. False if the bytes are
// not a usable compound file.
bool cfbf_parse(const Reader& r, size_t base, Cfbf& out);

// Reassemble a stream's bytes by following its sector chain. False if the chain
// is broken, loops, or runs outside the file.
bool cfbf_stream(const Reader& r, size_t base, const Cfbf& c, const CfbfEntry& e,
                 std::vector<uint8_t>& out);

}  // namespace ft

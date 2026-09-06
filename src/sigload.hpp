// sigload.hpp — load signature definitions from TOML, from a directory of files
// or from the sets embedded in the binary at build time (tools/embed_sigs.cpp).
#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <vector>

#include "signature.hpp"

namespace ft {

struct LoadResult {
    std::vector<Signature> signatures;
    std::vector<std::string> errors;  // one per file that failed to load
};

// Load every *.toml in `dir`. Malformed files are skipped and reported in
// errors, never fatal.
LoadResult load_signatures(const std::string& dir);

// One TOML document embedded in the binary: its file name (for error messages)
// and its bytes. Provided by the generated signatures_embedded.cpp.
struct EmbeddedToml {
    const char* name;
    const char* data;
    std::size_t size;
};
std::span<const EmbeddedToml> embedded_curated();     // signatures/*.toml
std::span<const EmbeddedToml> embedded_firmware();    // signatures-firmware/*.toml
std::span<const EmbeddedToml> embedded_generated();   // signatures-generated/*.toml (--broad)

// Parse a set of embedded TOML documents (same rules as load_signatures).
LoadResult load_signatures_from_memory(std::span<const EmbeddedToml> docs);

// Drop signatures from `lower` that are redundant magic-only duplicates of an
// authoritative (validator-backed) signature in `authoritative`. The imported
// firmware/generated DBs carry generic, magic-only entries (no validator, no hard
// constraints) whose magic collides with a purpose-built curated signature — e.g.
// a bare "ANDROID!" match alongside the validated android_boot. Since the curated
// validator is the authority on that magic (it accepts or rejects), the generic
// twin only adds low-tier false positives. A `lower` entry is dropped iff it has
// no validator, no hard constraints, and every one of its magics (at its offset)
// is claimed by an authoritative signature. Returns the number dropped.
size_t drop_redundant_generic_signatures(std::vector<Signature>& lower,
                                         const std::vector<Signature>& authoritative);

}  // namespace ft

// scheme.hpp — the vendor-descramble scheme registry.
//
// Each scheme recognizes one vendor's transformed-payload format by a header
// magic, reverses the transform (see cipher.hpp),
// and validates the result by an expected plaintext magic. The engine is used in
// two places: the `deobf` validator probes cheaply at identify time (first-block
// decrypt, read-only, no disk) to report "<scheme> (encrypted[, decryptable])";
// the descramble extractor runs the full transform under -e and hands the
// plaintext back to the extraction recursion.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "reader.hpp"

namespace ft {

struct DescrambleResult {
    std::vector<uint8_t> data;  // the recovered plaintext (empty when probe_only)
    std::string scheme;         // e.g. "dlink_shrs"
    std::string cipher;         // e.g. "AES-128-CBC"
    std::string key_desc;       // key id / description, for the manifest
    std::string validated;      // the plaintext magic that confirmed it (e.g. "uimage")
    size_t src_offset = 0;      // start of the ciphertext within the input
    size_t src_len = 0;         // ciphertext length
    size_t total_span = 0;      // header + ciphertext, for the finding size
};

// Result of a cheap identify-time probe: the scheme's header matched; `validated`
// says whether a first-block decrypt confirmed a working key/transform.
struct SchemeProbe {
    std::string scheme;
    std::string cipher;
    size_t total_span = 0;
    bool validated = false;  // a working key produced the expected plaintext magic
};

// Identify-time: does a known scheme's header sit at `offset`? Runs the cheap
// first-block probe. Read-only; no full decryption. nullopt if no scheme matches.
std::optional<SchemeProbe> probe_scheme(const Reader& r, size_t offset);

// Extract-time: run the scheme named `scheme` at `offset` in full, validate the
// plaintext, and return it. nullopt if the header/scheme does not match or the
// plaintext fails validation (never emit unvalidated bytes into the recursion).
std::optional<DescrambleResult> descramble(const Reader& r, size_t offset, const std::string& scheme);

// True if `name` is a registered descramble scheme (routes extraction to the
// descramble extractor). Also the set the `deobf` validator recognizes.
bool is_scheme(const std::string& name);

}  // namespace ft

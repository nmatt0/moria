// cipher.hpp — internal cipher primitives for the vendor-descramble layer.
//
// Firmware descrambling needs a small, closed set of transforms (see
// the design notes): AES-CBC, an OpenSSL-style KDF, a repeating
// XOR, a byte/block permutation, and the PC1 stream cipher. They are all
// implemented internally (no libcrypto dependency, matching the internal-LZO
// precedent) so the layer stays offline and fuzzable. This header declares the
// primitives; schemes (scheme.hpp) compose them with per-vendor key material.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ft {

// AES-128 or AES-256 in CBC mode, decryption only. `key` must be 16 or 32 bytes;
// `iv` 16 bytes; `data` a multiple of 16 (else nullopt). `strip_pkcs7` removes
// PKCS#7 padding from the final block when true (and validates it); when false
// the raw decrypted bytes are returned (the many firmware schemes that pad the
// plaintext to a block boundary by other means). Never throws.
std::optional<std::vector<uint8_t>> aes_cbc_decrypt(std::span<const uint8_t> data,
                                                    std::span<const uint8_t> key,
                                                    std::span<const uint8_t> iv, bool strip_pkcs7);

// SHA-256, MD5, and SHA-1 digests (SHA-256/MD5 feed the KDF; SHA-1 feeds the
// HMAC key derivation the D-Link TLV scheme uses).
std::array<uint8_t, 32> sha256(std::span<const uint8_t> data);
std::array<uint8_t, 16> md5(std::span<const uint8_t> data);
std::array<uint8_t, 20> sha1(std::span<const uint8_t> data);

// HMAC-SHA1(key, message) -> 20 bytes.
std::array<uint8_t, 20> hmac_sha1(std::span<const uint8_t> key, std::span<const uint8_t> message);

// Which digest a KDF uses.
enum class Hash { MD5, SHA256 };

// OpenSSL's EVP_BytesToKey: derive `key_len + iv_len` bytes from a passphrase and
// an optional salt by iterating `D_i = H(D_{i-1} ‖ pass ‖ salt)` (D_0 empty) and
// concatenating. Returns {key(key_len), iv(iv_len)} — matches `openssl enc` with
// no `-iter` (the classic KDF used by the D-Link OpenSSL-format schemes).
struct KeyIv {
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
};
KeyIv evp_bytes_to_key(std::span<const uint8_t> pass, std::span<const uint8_t> salt, Hash h,
                       size_t key_len, size_t iv_len);

}  // namespace ft

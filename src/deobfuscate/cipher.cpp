// cipher.cpp — internal AES-CBC (decrypt). Standard FIPS-197 byte-oriented
// implementation written for moria without an outside encryption library. Unit
// tests compare it with the published FIPS-197 AES-128 and AES-256 examples.
#include "deobfuscate/cipher.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace ft {

namespace {

// Rijndael inverse S-box (used for decryption).
constexpr std::array<uint8_t, 256> kInvSbox = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// Forward S-box (used only by key expansion via SubWord).
constexpr std::array<uint8_t, 256> kSbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

// GF(2^8) multiply.
uint8_t xtime(uint8_t x) { return static_cast<uint8_t>((x << 1) ^ ((x >> 7) * 0x1b)); }
uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// Expanded key schedule: Nr+1 round keys of 16 bytes each.
struct KeySchedule {
    std::array<uint8_t, 240> rk{};  // max for AES-256 (15 round keys * 16)
    int nr = 0;                     // number of rounds (10 for AES-128, 14 for AES-256)
};

bool expand_key(std::span<const uint8_t> key, KeySchedule& ks) {
    int nk;  // key length in 32-bit words
    if (key.size() == 16) { nk = 4; ks.nr = 10; }
    else if (key.size() == 32) { nk = 8; ks.nr = 14; }
    else return false;

    const int total_words = 4 * (ks.nr + 1);
    std::array<std::array<uint8_t, 4>, 60> w{};  // max 4*(14+1)=60 words
    for (int i = 0; i < nk; ++i)
        for (int j = 0; j < 4; ++j) w[i][j] = key[i * 4 + j];

    uint8_t rcon = 1;
    for (int i = nk; i < total_words; ++i) {
        std::array<uint8_t, 4> t = w[i - 1];
        if (i % nk == 0) {
            // RotWord + SubWord + Rcon
            uint8_t tmp = t[0];
            t[0] = kSbox[t[1]] ^ rcon;
            t[1] = kSbox[t[2]];
            t[2] = kSbox[t[3]];
            t[3] = kSbox[tmp];
            rcon = xtime(rcon);
        } else if (nk > 6 && i % nk == 4) {
            for (auto& b : t) b = kSbox[b];
        }
        for (int j = 0; j < 4; ++j) w[i][j] = w[i - nk][j] ^ t[j];
    }
    for (int i = 0; i < total_words; ++i)
        for (int j = 0; j < 4; ++j) ks.rk[i * 4 + j] = w[i][j];
    return true;
}

void add_round_key(uint8_t state[16], const uint8_t* rk) {
    for (int i = 0; i < 16; ++i) state[i] ^= rk[i];
}
void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) state[i] = kInvSbox[state[i]];
}
// State is column-major (s[r + 4c]); InvShiftRows rotates row r right by r.
void inv_shift_rows(uint8_t s[16]) {
    uint8_t t;
    // row 1: right rotate by 1
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    // row 2: right rotate by 2 (swap pairs)
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    // row 3: right rotate by 3 == left rotate by 1
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}
void inv_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = s + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        col[1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        col[2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
        col[3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
}

void decrypt_block(const KeySchedule& ks, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    std::memcpy(s, in, 16);
    add_round_key(s, &ks.rk[ks.nr * 16]);
    for (int round = ks.nr - 1; round >= 1; --round) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, &ks.rk[round * 16]);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, &ks.rk[0]);
    std::memcpy(out, s, 16);
}

}  // namespace

std::optional<std::vector<uint8_t>> aes_cbc_decrypt(std::span<const uint8_t> data,
                                                    std::span<const uint8_t> key,
                                                    std::span<const uint8_t> iv, bool strip_pkcs7) {
    if (iv.size() != 16) return std::nullopt;
    if (data.empty() || data.size() % 16 != 0) return std::nullopt;
    KeySchedule ks;
    if (!expand_key(key, ks)) return std::nullopt;

    std::vector<uint8_t> out(data.size());
    uint8_t prev[16];
    std::memcpy(prev, iv.data(), 16);
    for (size_t off = 0; off < data.size(); off += 16) {
        uint8_t block[16];
        decrypt_block(ks, data.data() + off, block);
        for (int i = 0; i < 16; ++i) out[off + i] = block[i] ^ prev[i];
        std::memcpy(prev, data.data() + off, 16);
    }
    if (strip_pkcs7) {
        uint8_t pad = out.back();
        if (pad == 0 || pad > 16 || pad > out.size()) return std::nullopt;
        for (size_t i = out.size() - pad; i < out.size(); ++i)
            if (out[i] != pad) return std::nullopt;
        out.resize(out.size() - pad);
    }
    return out;
}

// ---------------------------------------------------------------- SHA-256
namespace {
inline uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
constexpr std::array<uint32_t, 64> kK256 = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
}  // namespace

std::array<uint8_t, 32> sha256(std::span<const uint8_t> data) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    // Pad: message + 0x80 + zeros + 64-bit big-endian bit length, to a 64-byte multiple.
    std::vector<uint8_t> m(data.begin(), data.end());
    uint64_t bits = static_cast<uint64_t>(data.size()) * 8;
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0);
    for (int i = 7; i >= 0; --i) m.push_back(static_cast<uint8_t>(bits >> (i * 8)));

    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(m[off + i * 4]) << 24) | (uint32_t(m[off + i * 4 + 1]) << 16) |
                   (uint32_t(m[off + i * 4 + 2]) << 8) | uint32_t(m[off + i * 4 + 3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + kK256[i] + w[i];
            uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    std::array<uint8_t, 32> out;
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j) out[i * 4 + j] = static_cast<uint8_t>(h[i] >> ((3 - j) * 8));
    return out;
}

// ---------------------------------------------------------------- MD5
namespace {
inline uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
constexpr std::array<uint32_t, 64> kKmd5 = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
constexpr std::array<int, 64> kSmd5 = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                       5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
}  // namespace

std::array<uint8_t, 16> md5(std::span<const uint8_t> data) {
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    std::vector<uint8_t> m(data.begin(), data.end());
    uint64_t bits = static_cast<uint64_t>(data.size()) * 8;
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0);
    for (int i = 0; i < 8; ++i) m.push_back(static_cast<uint8_t>(bits >> (i * 8)));  // little-endian

    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; ++i)
            w[i] = uint32_t(m[off + i * 4]) | (uint32_t(m[off + i * 4 + 1]) << 8) |
                   (uint32_t(m[off + i * 4 + 2]) << 16) | (uint32_t(m[off + i * 4 + 3]) << 24);
        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (int i = 0; i < 64; ++i) {
            uint32_t F;
            int g;
            if (i < 16) { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
            else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
            else { F = C ^ (B | ~D); g = (7 * i) % 16; }
            F += A + kKmd5[i] + w[g];
            A = D; D = C; C = B;
            B += rol32(F, kSmd5[i]);
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }
    std::array<uint8_t, 16> out;
    uint32_t hs[4] = {a0, b0, c0, d0};
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j) out[i * 4 + j] = static_cast<uint8_t>(hs[i] >> (j * 8));
    return out;
}

// ---------------------------------------------------------------- SHA-1
std::array<uint8_t, 20> sha1(std::span<const uint8_t> data) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    std::vector<uint8_t> m(data.begin(), data.end());
    uint64_t bits = static_cast<uint64_t>(data.size()) * 8;
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0);
    for (int i = 7; i >= 0; --i) m.push_back(static_cast<uint8_t>(bits >> (i * 8)));  // big-endian

    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(m[off + i * 4]) << 24) | (uint32_t(m[off + i * 4 + 1]) << 16) |
                   (uint32_t(m[off + i * 4 + 2]) << 8) | uint32_t(m[off + i * 4 + 3]);
        for (int i = 16; i < 80; ++i) w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t t = rol32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol32(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    std::array<uint8_t, 20> out;
    for (int i = 0; i < 5; ++i)
        for (int j = 0; j < 4; ++j) out[i * 4 + j] = static_cast<uint8_t>(h[i] >> ((3 - j) * 8));
    return out;
}

std::array<uint8_t, 20> hmac_sha1(std::span<const uint8_t> key, std::span<const uint8_t> message) {
    constexpr size_t B = 64;  // SHA-1 block size
    std::array<uint8_t, B> k0{};
    if (key.size() > B) {
        auto hk = sha1(key);
        std::copy(hk.begin(), hk.end(), k0.begin());
    } else {
        std::copy(key.begin(), key.end(), k0.begin());
    }
    std::vector<uint8_t> ipad(B), opad(B);
    for (size_t i = 0; i < B; ++i) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    std::vector<uint8_t> inner(ipad);
    inner.insert(inner.end(), message.begin(), message.end());
    auto ih = sha1(inner);
    std::vector<uint8_t> outer(opad);
    outer.insert(outer.end(), ih.begin(), ih.end());
    return sha1(outer);
}

KeyIv evp_bytes_to_key(std::span<const uint8_t> pass, std::span<const uint8_t> salt, Hash h,
                       size_t key_len, size_t iv_len) {
    std::vector<uint8_t> material;
    std::vector<uint8_t> d;  // previous digest (empty at start)
    while (material.size() < key_len + iv_len) {
        std::vector<uint8_t> in;
        in.insert(in.end(), d.begin(), d.end());
        in.insert(in.end(), pass.begin(), pass.end());
        in.insert(in.end(), salt.begin(), salt.end());
        if (h == Hash::SHA256) {
            auto dig = sha256(in);
            d.assign(dig.begin(), dig.end());
        } else {
            auto dig = md5(in);
            d.assign(dig.begin(), dig.end());
        }
        material.insert(material.end(), d.begin(), d.end());
    }
    KeyIv out;
    out.key.assign(material.begin(), material.begin() + key_len);
    out.iv.assign(material.begin() + key_len, material.begin() + key_len + iv_len);
    return out;
}

}  // namespace ft

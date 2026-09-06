// unit_tests.cpp — direct tests of the engine primitives (expr, layout, resolve,
// ahocorasick). No framework: a CHECK macro + main. Built as `moria_unit`.
#include <cstdint>
#include <cstdio>
#include <functional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include <cmath>

#include "ahocorasick.hpp"
#include "crc32.hpp"
#include "entropy.hpp"
#include "expr.hpp"
#include "extract/lzo1x.hpp"
#include "finding.hpp"
#include "layout.hpp"
#include "mime.hpp"
#include "deobfuscate/cipher.hpp"
#include "reader.hpp"
#include "resolve.hpp"

static int g_checks = 0, g_fails = 0;
#define CHECK(cond)                                                        \
    do {                                                                   \
        ++g_checks;                                                        \
        if (!(cond)) {                                                     \
            ++g_fails;                                                     \
            std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                  \
    } while (0)

// ---------------------------------------------------------------- expr
static uint64_t E(const char* s, std::function<uint64_t(const std::string&)> r = {}) {
    auto e = ft::parse_expr(s);
    return ft::eval_expr(*e, r ? r : [](const std::string&) { return 0ull; });
}

static void test_expr() {
    CHECK(E("1+2*3") == 7);           // precedence
    CHECK(E("(1+2)*3") == 9);         // parens
    CHECK(E("1<<4") == 16);           // shift
    CHECK(E("0x10") == 16);           // hex literal
    CHECK(E("6 & 3") == 2);
    CHECK(E("6 | 1") == 7);
    CHECK(E("5 % 2") == 1);
    CHECK(E("10 / 3") == 3);
    CHECK(E("5 in 1..10") == 1);
    CHECK(E("11 in 1..10") == 0);
    CHECK(E("1 == 1 && 2 == 2") == 1);
    CHECK(E("1 == 2 || 3 == 3") == 1);
    CHECK(E("!0") == 1);
    CHECK(E("!5") == 0);
    CHECK(E("2 > 1") == 1 && E("1 >= 1") == 1 && E("1 != 2") == 1);
    CHECK(E("~0") == 0xFFFFFFFFFFFFFFFFull);
    // variables + a real constraint shape
    auto fields = [](const std::string& n) -> uint64_t {
        if (n == "block_size") return 131072;
        if (n == "block_log") return 17;
        if (n == "_avail") return 4096;
        return 0;
    };
    CHECK(E("block_size == 1 << block_log", fields) == 1);
    CHECK(E("block_log in 10..20", fields) == 1);
    CHECK(E("x + 1", [](const std::string& n) { return n == "x" ? 41ull : 0ull; }) == 42);
    // division/shift-by-large guards don't crash
    CHECK(E("1 / 0") == 0);
    CHECK(E("1 << 99") == 0);
}

// ---------------------------------------------------------------- layout
static void test_layout() {
    auto lay = ft::Layout::parse("u32 a; u16 b; bytes[4] c; u8 d; i8 s;");
    // offsets: a@0 b@4 c@6 d@10 s@11  (span 12)
    CHECK(lay.span == 12);
    std::vector<uint8_t> buf = {0x01, 0x00, 0x00, 0x00,  // a = 1 (LE)
                                0x02, 0x00,              // b = 2
                                0xAA, 0xBB, 0xCC, 0xDD,  // c bytes (skipped)
                                0x07,                    // d = 7
                                0xFF};                   // s = -1
    ft::Reader r(std::span<const uint8_t>(buf.data(), buf.size()));
    auto le = lay.extract(r, 0, ft::Endian::Little);
    CHECK(le.has_value());
    CHECK((*le)["a"] == 1);
    CHECK((*le)["b"] == 2);
    CHECK((*le)["d"] == 7);
    CHECK((*le)["s"] == 0xFFFFFFFFFFFFFFFFull);  // i8 0xFF sign-extended
    CHECK(le->count("c") == 0);                  // bytes[] not stored as an int field
    // big-endian reads the same bytes differently
    auto be = lay.extract(r, 0, ft::Endian::Big);
    CHECK((*be)["a"] == 0x01000000u);
    // OOB: struct doesn't fit -> nullopt
    ft::Reader small(std::span<const uint8_t>(buf.data(), 8));
    CHECK(!lay.extract(small, 0, ft::Endian::Little).has_value());
}

// ---------------------------------------------------------------- resolve
static ft::Finding mk(size_t off, size_t size, ft::Confidence c, const char* type,
                      const char* cat = "filesystem") {
    ft::Finding f;
    f.offset = off;
    f.size = size;
    f.type = type;
    f.category = cat;
    f.set_confidence(c, "test");
    return f;
}

static void test_resolve() {
    using ft::Confidence;
    std::set<std::string> none;

    // Same offset: higher confidence wins; loser retained in also_matched.
    {
        std::vector<ft::Finding> in = {mk(0, 100, Confidence::Structural, "a"),
                                       mk(0, 100, Confidence::Verified, "b")};
        auto out = ft::resolve(in, 100, none);
        CHECK(out.size() == 1);
        CHECK(out[0].type == "b");
        CHECK(out[0].also_matched.size() == 1 && out[0].also_matched[0].type == "a");
    }
    // Determinism: identical input -> identical output (no random tiebreak).
    {
        std::vector<ft::Finding> in = {mk(0, 10, Confidence::Structural, "x"),
                                       mk(0, 10, Confidence::Structural, "y")};
        auto a = ft::resolve(in, 10, none);
        auto b = ft::resolve(in, 10, none);
        CHECK(a.size() == 1 && b.size() == 1 && a[0].type == b[0].type);
        CHECK(a[0].type == "x");  // tiebreak by type name, deterministic
    }
    // Containment: a finding starting inside a confident sized region is suppressed.
    {
        std::vector<ft::Finding> in = {mk(0, 100, Confidence::Consistent, "outer"),
                                       mk(50, 10, Confidence::Structural, "inner")};
        auto out = ft::resolve(in, 100, none);
        CHECK(out.size() == 1 && out[0].type == "outer");
        CHECK(out[0].also_matched.size() == 1 && out[0].also_matched[0].type == "inner");
    }
    // Size inference: unknown-size finding runs to the next finding.
    {
        std::vector<ft::Finding> in = {mk(0, 0, Confidence::Structural, "a"),
                                       mk(64, 10, Confidence::Structural, "b")};
        auto out = ft::resolve(in, 1000, none);
        CHECK(out.size() == 2);
        CHECK(out[0].size == 64);  // inferred to next offset
    }
    // Coalesce: adjacent same-set findings merge into one region.
    {
        std::set<std::string> co = {"jffs2"};
        std::vector<ft::Finding> in = {mk(0, 50, Confidence::Structural, "jffs2"),
                                       mk(50, 50, Confidence::Structural, "jffs2")};
        auto out = ft::resolve(in, 100, co);
        CHECK(out.size() == 1);
        CHECK(out[0].size == 100 && out[0].coalesced_count == 2);
    }
}

// ---------------------------------------------------------------- aho-corasick
static void test_ahocorasick() {
    ft::AhoCorasick ac;
    ac.add({'h', 'e'}, 0);
    ac.add({'s', 'h', 'e'}, 1);
    ac.add({'h', 'i', 's'}, 2);
    ac.add({'h', 'e', 'r', 's'}, 3);
    ac.build();
    std::string text = "ushers";
    std::span<const uint8_t> data(reinterpret_cast<const uint8_t*>(text.data()), text.size());

    std::vector<std::pair<size_t, uint32_t>> hits;
    ac.find(data, 0, [&](size_t off, uint32_t id) {
        hits.push_back({off, id});
        return true;
    });
    // "ushers" contains she@1, he@2, hers@2 (overlapping all reported).
    bool she = false, he = false, hers = false;
    for (auto [off, id] : hits) {
        if (id == 1 && off == 1) she = true;
        if (id == 0 && off == 2) he = true;
        if (id == 3 && off == 2) hers = true;
    }
    CHECK(she && he && hers);

    // Early stop: returning false halts the scan.
    int count = 0;
    ac.find(data, 0, [&](size_t, uint32_t) {
        ++count;
        return false;
    });
    CHECK(count == 1);
}

// ---------------------------------------------------------------- crc32 variants
static void test_crc32() {
    std::string s = "123456789";
    std::span<const uint8_t> d(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    CHECK(ft::crc32_ieee(d) == 0xCBF43926u);   // standard CRC-32 check value
    CHECK(ft::crc32_jffs2(d) == 0x2DFD2D88u);  // init 0, no invert
    CHECK(ft::crc32_ubi(d) == 0x340BC6D9u);    // init 0xFFFFFFFF, no invert
    CHECK(ft::crc32_raw(0, d) == ft::crc32_jffs2(d));
}

// ---------------------------------------------------------------- entropy
static void test_entropy() {
    std::vector<uint8_t> zeros(256, 0);
    CHECK(std::fabs(ft::shannon_entropy(std::span<const uint8_t>(zeros)) - 0.0) < 1e-9);

    std::vector<uint8_t> all256(256);
    for (int i = 0; i < 256; ++i) all256[i] = static_cast<uint8_t>(i);
    CHECK(std::fabs(ft::shannon_entropy(std::span<const uint8_t>(all256)) - 8.0) < 1e-9);

    std::vector<uint8_t> two(256);
    for (int i = 0; i < 256; ++i) two[i] = (i & 1);
    CHECK(std::fabs(ft::shannon_entropy(std::span<const uint8_t>(two)) - 1.0) < 1e-9);

    CHECK(ft::shannon_entropy(std::span<const uint8_t>()) == 0.0);  // empty
}

// Known-answer LZO1X vectors: raw lzo1x_1 streams (header=False) from
// python-lzo 2.10 (liblzo2), with the exact bytes they decompress to.
static bool lzo_ok(const std::vector<uint8_t>& comp, const std::vector<uint8_t>& expect) {
    std::vector<uint8_t> out(expect.size());
    size_t got = 0;
    bool ok = ft::lzo1x_decompress_safe(comp.data(), comp.size(), out.data(), out.size(), &got);
    return ok && got == expect.size() && out == expect;
}

static void test_lzo1x() {
    struct Vec {
        std::vector<uint8_t> comp, plain;
    };
    const std::vector<Vec> vecs = {
        {{0x00,0x0d,0x74,0x68,0x65,0x20,0x71,0x75,0x69,0x63,0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,0x66,0x6f,0x78,0x20,0x6a,0x75,0x6d,0x70,0x73,0x20,0x6f,0x76,0x65,0x72,0x20,0x78,0x03,0x00,0x0b,0x6c,0x61,0x7a,0x79,0x20,0x64,0x6f,0x67,0x2c,0x20,0x74,0x68,0x65,0x20,0x71,0x75,0x69,0x63,0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,0x66,0x6f,0x78,0x11,0x00,0x00},
         {0x74,0x68,0x65,0x20,0x71,0x75,0x69,0x63,0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,0x66,0x6f,0x78,0x20,0x6a,0x75,0x6d,0x70,0x73,0x20,0x6f,0x76,0x65,0x72,0x20,0x74,0x68,0x65,0x20,0x6c,0x61,0x7a,0x79,0x20,0x64,0x6f,0x67,0x2c,0x20,0x74,0x68,0x65,0x20,0x71,0x75,0x69,0x63,0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,0x66,0x6f,0x78}},
        {{0x02,0x00,0x00,0x00,0x00,0x00,0x20,0x0b,0x10,0x00,0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00},
         std::vector<uint8_t>(64, 0x00)},
        {{0x2f,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x11,0x00,0x00},
         {0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43,0x41,0x42,0x43}},
        {{0x05,0x68,0x65,0x61,0x64,0x65,0x72,0x3a,0xff,0x32,0x00,0x00,0x0d,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x74,0x72,0x61,0x69,0x6c,0x65,0x72,0x11,0x00,0x00},
         {0x68,0x65,0x61,0x64,0x65,0x72,0x3a,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x74,0x72,0x61,0x69,0x6c,0x65,0x72}},
    };
    for (const auto& v : vecs) CHECK(lzo_ok(v.comp, v.plain));

    // Malformed streams must fail cleanly (return false), never crash.
    std::vector<uint8_t> out(64);
    size_t got = 0;
    CHECK(!ft::lzo1x_decompress_safe(vecs[0].comp.data(), 3, out.data(), out.size(), &got));  // truncated
    const std::vector<uint8_t> garbage = {0xff, 0xff, 0xff, 0xff};
    CHECK(!ft::lzo1x_decompress_safe(garbage.data(), garbage.size(), out.data(), 2, &got));  // out too small
    // Empty input decodes to empty output.
    CHECK(ft::lzo1x_decompress_safe(nullptr, 0, out.data(), out.size(), &got) && got == 0);
}

static void test_mime() {
    // Registered types verbatim; firmware types get a specific x- form (not
    // the useless application/octet-stream that `file` returns); `file`'s own
    // specific spellings are matched; unknown -> octet-stream.
    CHECK(std::string(ft::mime_for_type("gzip")) == "application/gzip");
    CHECK(std::string(ft::mime_for_type("png")) == "image/png");
    CHECK(std::string(ft::mime_for_type("squashfs")) == "application/x-squashfs");
    CHECK(std::string(ft::mime_for_type("squashfs_legacy")) == "application/x-squashfs");
    CHECK(std::string(ft::mime_for_type("uimage")) == "application/x-uimage");
    CHECK(std::string(ft::mime_for_type("elf")) == "application/x-executable");
    CHECK(std::string(ft::mime_for_type("ihex")) == "text/x-hex");
    CHECK(std::string(ft::mime_for_type("iso9660")) == "application/x-iso9660-image");
    CHECK(std::string(ft::mime_for_type("private_key")) == "application/x-pem-file");
    CHECK(std::string(ft::mime_for_type("fat32")) == "application/x-fat");
    CHECK(std::string(ft::mime_for_type("nonesuch")) == "application/octet-stream");
}

// ---------------------------------------------------------------- aes (deobf)
static std::vector<uint8_t> unhex(const char* s) {
    auto v = [](char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; };
    std::vector<uint8_t> out;
    for (; s[0] && s[1]; s += 2) out.push_back(static_cast<uint8_t>(v(s[0]) * 16 + v(s[1])));
    return out;
}
static void test_aes() {
    std::vector<uint8_t> iv(16, 0);
    // FIPS-197 known-answer vectors (single block, IV=0 -> CBC == ECB): decrypt.
    auto k128 = unhex("000102030405060708090a0b0c0d0e0f");
    auto ct128 = unhex("69c4e0d86a7b0430d8cdb78070b4c55a");
    auto k256 = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto ct256 = unhex("8ea2b7ca516745bfeafc49904b496089");
    auto pt = unhex("00112233445566778899aabbccddeeff");
    auto r128 = ft::aes_cbc_decrypt(ct128, k128, iv, false);
    auto r256 = ft::aes_cbc_decrypt(ct256, k256, iv, false);
    CHECK(r128 && *r128 == pt);
    CHECK(r256 && *r256 == pt);
    // Bad sizes rejected.
    CHECK(!ft::aes_cbc_decrypt(ct128, unhex("0011"), iv, false));         // short key
    CHECK(!ft::aes_cbc_decrypt(unhex("001122"), k128, iv, false));        // non-block input
    CHECK(!ft::aes_cbc_decrypt(ct128, k128, unhex("0000"), false));       // short IV

    // SHA-256 / MD5 known-answer ("abc"), and EVP_BytesToKey vs `openssl -nosalt`.
    std::vector<uint8_t> abc = {'a', 'b', 'c'};
    auto s = ft::sha256(abc);
    auto m = ft::md5(abc);
    CHECK(std::vector<uint8_t>(s.begin(), s.end()) ==
          unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK(std::vector<uint8_t>(m.begin(), m.end()) == unhex("900150983cd24fb0d6963f7d28e17f72"));
    std::vector<uint8_t> pw = {'t', 'e', 's', 't'};
    auto ki = ft::evp_bytes_to_key(pw, {}, ft::Hash::SHA256, 32, 16);
    CHECK(ki.key == unhex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
    CHECK(ki.iv == unhex("206dfc4e0335fa0ad986b9c1942dd653"));

    // SHA-1 + HMAC-SHA1 known-answers (used by the D-Link TLV key derivation).
    auto s1 = ft::sha1(abc);
    CHECK(std::vector<uint8_t>(s1.begin(), s1.end()) ==
          unhex("a9993e364706816aba3e25717850c26c9cd0d89d"));
    std::vector<uint8_t> hk = {'k', 'e', 'y'};
    std::string hmsg = "The quick brown fox jumps over the lazy dog";
    std::vector<uint8_t> hm(hmsg.begin(), hmsg.end());
    auto hs = ft::hmac_sha1(hk, hm);
    CHECK(std::vector<uint8_t>(hs.begin(), hs.end()) ==
          unhex("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"));
}

int main() {
    test_expr();
    test_layout();
    test_resolve();
    test_ahocorasick();
    test_crc32();
    test_entropy();
    test_lzo1x();
    test_mime();
    test_aes();
    std::printf("unit: %d checks, %d failures\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}

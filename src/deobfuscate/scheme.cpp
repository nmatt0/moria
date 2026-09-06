// scheme.cpp — vendor-descramble scheme registry. See scheme.hpp and
// the research notes. One function per scheme; a small table maps a
// scheme name to it. Add a scheme = add a function + a table row (+ a signature
// TOML so identify surfaces it).
#include "deobfuscate/scheme.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "deobfuscate/cipher.hpp"

namespace ft {

namespace {

// A scheme reverses a transform at `offset`. `probe_only` decrypts just enough to
// validate the plaintext magic (cheap, identify-time); otherwise it recovers the
// whole payload. Returns nullopt if the header does not match or validation fails.
using SchemeFn = std::optional<DescrambleResult> (*)(const Reader&, size_t, bool);

bool starts_with(const Reader& r, size_t off, const uint8_t* magic, size_t n) {
    auto b = r.bytes(off, n);
    return b && std::memcmp(b->data(), magic, n) == 0;
}

std::optional<std::vector<uint8_t>> hex_decode(std::span<const uint8_t> s) {
    if (s.size() % 2) return std::nullopt;
    auto v = [](uint8_t c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        c |= 0x20;
        return (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
    };
    std::vector<uint8_t> out(s.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        int h = v(s[i * 2]), l = v(s[i * 2 + 1]);
        if (h < 0 || l < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>(h * 16 + l);
    }
    return out;
}

std::vector<uint8_t> read_cstr(const Reader& r, size_t off, size_t maxlen) {
    std::vector<uint8_t> out;
    auto b = r.bytes(off, maxlen);
    if (!b) return out;
    for (uint8_t c : *b) {
        if (c == 0) break;
        out.push_back(c);
    }
    return out;
}

std::string to_hex(std::span<const uint8_t> b) {
    static const char* h = "0123456789abcdef";
    std::string s;
    for (uint8_t c : b) {
        s += h[c >> 4];
        s += h[c & 0xF];
    }
    return s;
}

// The 16 D-Link device passphrases shared by the MH01 and DLK schemes (hex
// strings used verbatim as the passphrase). Ref: delink mh01.rs known_keys().
// Provisional until verified against a real device image; add a row as recovered.
const char* kDlinkDeviceKeys[] = {
    "044b4e59846ecee953662ff2238fcc23", "927fc5786df1a9557524a0289e1e3f3b",  // E15
    "4d5ee2c8b5d0fdd9a9a2d351ba897752", "238a29b9432f688e30b701548c753146",  // E30
    "a4f7c17c3e0aa4532c2024ce6ac5f17c", "6b5a65dbc1ebc492ac6d8efbbb59ae09",  // R12
    "70070e579f97548a96a7794d4d779376", "7b4df82f7f042b9d0b40971be0ff53c4",  // R15
    "6276ccf4c1d8d6f54b481095e78ff97f",                                       // R18
    "1ae6c79be7d069ca74df7670bdfc4952",                                       // M18
    "b4517d9b98e04d9f075f5e78c743e097", "05c79b73cf88619d7b9725505cfd718f",  // M30
    "6b29f1d663a21b35fb45b69a42649f5e", "1bfb1004e29f9eb76dbe26eb0dd87cd1",  // M32
    "c5f8a1e22f808abc84f2e4a6fa5f10bb", "6420da70a975455e4ddd6b8fa5b652e7",  // M60
};

// ---- D-Link SHRS: AES-128-CBC, fixed key, IV in the header, plaintext is a
// uImage. Ref: delink shrs.rs / 0xricksanchez dlink-decrypt. ----
std::optional<DescrambleResult> shrs(const Reader& r, size_t off, bool probe_only) {
    static constexpr uint8_t kMagic[4] = {'S', 'H', 'R', 'S'};
    static constexpr uint8_t kUimage[4] = {0x27, 0x05, 0x19, 0x56};
    static constexpr uint8_t kKey[16] = {0xC0, 0x5F, 0xBF, 0x19, 0x36, 0xC9, 0x94, 0x29,
                                         0xCE, 0x2A, 0x07, 0x81, 0xF0, 0x8D, 0x6A, 0xD8};
    constexpr size_t kIvOff = 0x0C, kDataOff = 0x6DC, kSizeOff = 8;

    if (!starts_with(r, off, kMagic, 4)) return std::nullopt;
    auto enc_size = r.at<uint32_t>(off + kSizeOff, Endian::Big);
    auto iv = r.bytes(off + kIvOff, 16);
    if (!enc_size || !iv) return std::nullopt;
    size_t clen = *enc_size;
    if (clen == 0 || clen % 16 != 0) return std::nullopt;

    // Probe: decrypt only the first block and check the uImage magic (offset 0).
    size_t take = probe_only ? 16 : clen;
    auto cipher = r.bytes(off + kDataOff, take);
    if (!cipher) return std::nullopt;
    auto plain = aes_cbc_decrypt(*cipher, kKey, *iv, /*strip_pkcs7=*/false);
    if (!plain || plain->size() < 4 || std::memcmp(plain->data(), kUimage, 4) != 0)
        return std::nullopt;

    DescrambleResult res;
    res.scheme = "dlink_shrs";
    res.cipher = "AES-128-CBC";
    res.key_desc = "fixed";
    res.validated = "uimage";
    res.src_offset = off + kDataOff;
    res.src_len = clen;
    res.total_span = kDataOff + clen;
    if (!probe_only) res.data = std::move(*plain);
    return res;
}

// ---- D-Link encrpted_img (DIR-X series): AES-256-CBC, fixed key + IV, the
// ciphertext (from offset 16) decrypted in independent 128 KiB blocks (IV reset
// per block), plaintext is a UBI image. Ref: delink encrpted.rs. ----
std::optional<DescrambleResult> encrpted_img(const Reader& r, size_t off, bool probe_only) {
    static constexpr uint8_t kMagic[12] = {'e', 'n', 'c', 'r', 'p', 't', 'e', 'd', '_', 'i', 'm', 'g'};
    static constexpr uint8_t kUbi[3] = {'U', 'B', 'I'};
    static constexpr uint8_t kKey[32] = {0x68, 0x65, 0x39, 0x2d, 0x34, 0x2b, 0x4d, 0x21,
                                         0x29, 0x64, 0x36, 0x3d, 0x6d, 0x7e, 0x77, 0x65,
                                         0x31, 0x2c, 0x71, 0x32, 0x61, 0x33, 0x64, 0x31,
                                         0x6e, 0x26, 0x32, 0x2a, 0x5a, 0x5e, 0x25, 0x38};
    static constexpr uint8_t kIv[16] = {0x4a, 0x25, 0x31, 0x69, 0x51, 0x6c, 0x38, 0x24,
                                        0x3d, 0x6c, 0x6d, 0x2d, 0x3b, 0x38, 0x41, 0x45};
    constexpr size_t kDataOff = 16, kBlock = 131072;
    std::span<const uint8_t> key(kKey, 32), iv(kIv, 16);

    if (!starts_with(r, off, kMagic, 12)) return std::nullopt;
    if (r.size() <= off + kDataOff) return std::nullopt;
    size_t clen = r.size() - off - kDataOff;
    clen -= clen % 16;  // whole AES blocks only
    if (clen == 0) return std::nullopt;

    std::vector<uint8_t> out;
    if (probe_only) {
        auto blk = r.bytes(off + kDataOff, 16);
        if (!blk) return std::nullopt;
        auto p = aes_cbc_decrypt(*blk, key, iv, false);
        if (!p || p->size() < 3 || std::memcmp(p->data(), kUbi, 3) != 0) return std::nullopt;
    } else {
        auto cipher = r.bytes(off + kDataOff, clen);
        if (!cipher) return std::nullopt;
        for (size_t p = 0; p < clen; p += kBlock) {
            size_t n = std::min(kBlock, clen - p);
            auto dec = aes_cbc_decrypt(cipher->subspan(p, n), key, iv, false);
            if (!dec) return std::nullopt;
            out.insert(out.end(), dec->begin(), dec->end());
        }
        if (out.size() < 3 || std::memcmp(out.data(), kUbi, 3) != 0) return std::nullopt;
    }

    DescrambleResult res;
    res.scheme = "dlink_encrpted_img";
    res.cipher = "AES-256-CBC";
    res.key_desc = "fixed";
    res.validated = "ubi";
    res.src_offset = off + kDataOff;
    res.src_len = clen;
    res.total_span = kDataOff + clen;
    if (!probe_only) res.data = std::move(out);
    return res;
}

// Does a decrypted buffer start with a recognizable firmware/container magic?
// Returns the type name (for provenance/validation) or "" if none. Used to
// confirm a trial decryption produced real firmware, not garbage.
const char* firmware_magic(std::span<const uint8_t> p) {
    auto at = [&](size_t o, const char* m, size_t n) {
        return p.size() >= o + n && std::memcmp(p.data() + o, m, n) == 0;
    };
    if (at(0, "hsqs", 4) || at(0, "sqsh", 4)) return "squashfs";
    if (at(0, "\x27\x05\x19\x56", 4)) return "uimage";
    if (at(0, "UBI#", 4) || at(0, "UBI!", 4)) return "ubi";
    if (at(0, "\xd0\x0d\xfe\xed", 4)) return "fdt";
    if (at(0x101, "ustar", 5)) return "tar";
    if (at(0, "\x1f\x8b", 2)) return "gzip";
    if (at(0, "\xfd""7zXZ", 6)) return "xz";
    if (at(0, "070701", 6) || at(0, "070702", 6)) return "cpio";
    if (at(0, "\x85\x19", 2)) return "jffs2";
    return "";
}

// ---- OpenSSL `Salted__` firmware: EVP_BytesToKey(password, salt) -> AES-256-CBC.
// A data-driven password table + a firmware-magic check covers the D-Link schemes
// that are just `openssl enc` output (dap1610, r95/M95/R36/M36). Add a recovered
// password = one table row. Ref: delink dap1610.rs / r95.rs. ----
std::optional<DescrambleResult> openssl_salted(const Reader& r, size_t off, bool probe_only) {
    static constexpr uint8_t kMagic[8] = {'S', 'a', 'l', 't', 'e', 'd', '_', '_'};
    static const char* kPasswords[] = {
        "2c3b6fa78bd60b41bb0796fef4b058b0",  // DAP-1610 B1 (-> tar)
        "CAD1C42B11F1982FFA94B6A24C260A43",  // R36 (-> fdt)
        "A11E331C15CE73ABA8E06171A11D2FB6",  // M36
        "BE81AE1B6F523AC7164C4FD67B6BD8FD",  // R95
        "91A9A3AF2218F4EA60AC37D5835EB318",  // M95
    };

    if (!starts_with(r, off, kMagic, 8)) return std::nullopt;
    auto salt = r.bytes(off + 8, 8);
    if (!salt || r.size() <= off + 16) return std::nullopt;
    size_t clen = r.size() - off - 16;
    clen -= clen % 16;
    if (clen == 0) return std::nullopt;

    // Probe decrypts a prefix (enough to see a tar magic at 0x101); a full run
    // decrypts everything and strips OpenSSL's PKCS#7 padding.
    size_t take = probe_only ? std::min<size_t>(clen, 512) : clen;
    auto cipher = r.bytes(off + 16, take);
    if (!cipher) return std::nullopt;

    for (const char* pw : kPasswords) {
        std::span<const uint8_t> pass(reinterpret_cast<const uint8_t*>(pw), std::strlen(pw));
        for (Hash h : {Hash::SHA256, Hash::MD5}) {
            auto ki = evp_bytes_to_key(pass, *salt, h, 32, 16);
            auto plain = aes_cbc_decrypt(*cipher, ki.key, ki.iv, /*strip_pkcs7=*/!probe_only);
            if (!plain) continue;
            const char* magic = firmware_magic(*plain);
            if (!*magic) continue;

            DescrambleResult res;
            res.scheme = "openssl_salted";
            res.cipher = "AES-256-CBC";
            res.key_desc = std::string("pw:") + (pw[0] ? std::string(pw).substr(0, 8) + "…" : "?") +
                           (h == Hash::MD5 ? " (md5)" : " (sha256)");
            res.validated = magic;
            res.src_offset = off + 16;
            res.src_len = clen;
            res.total_span = 16 + clen;
            if (!probe_only) res.data = std::move(*plain);
            return res;
        }
    }
    return std::nullopt;
}

// ---- D-Link MH01: header (0x41) with an ASCII-hex IV @32; the payload @0x41 is
// an OpenSSL Salted__ blob keyed by a device passphrase (EVP_BytesToKey SHA256,
// 16-byte AES-128 key) with the header IV; plaintext starts "MH01".
// Ref: delink mh01.rs. PROVISIONAL (unverified against a real image). ----
std::optional<DescrambleResult> mh01(const Reader& r, size_t off, bool probe_only) {
    static constexpr uint8_t kMagic[4] = {'M', 'H', '0', '1'};
    static constexpr uint8_t kSalted[8] = {'S', 'a', 'l', 't', 'e', 'd', '_', '_'};
    constexpr size_t kHdr = 0x41, kIvOff = 32, kSizeOff = 0x18;
    if (!starts_with(r, off, kMagic, 4)) return std::nullopt;
    auto encsz = r.at<uint32_t>(off + kSizeOff, Endian::Little);
    auto ivhex = r.bytes(off + kIvOff, 32);
    if (!encsz || !ivhex) return std::nullopt;
    auto iv = hex_decode(*ivhex);
    if (!iv || iv->size() != 16) return std::nullopt;
    size_t paylen = *encsz;
    if (paylen < 24 || (paylen - 16) % 16 != 0) return std::nullopt;
    auto payload = r.bytes(off + kHdr, paylen);
    if (!payload || std::memcmp(payload->data(), kSalted, 8) != 0) return std::nullopt;
    auto salt = payload->subspan(8, 8);
    auto ct = payload->subspan(16, paylen - 16);

    for (const char* pw : kDlinkDeviceKeys) {
        std::span<const uint8_t> pass(reinterpret_cast<const uint8_t*>(pw), std::strlen(pw));
        auto ki = evp_bytes_to_key(pass, salt, Hash::SHA256, 16, 0);
        auto take = probe_only ? ct.subspan(0, 16) : ct;
        auto plain = aes_cbc_decrypt(take, ki.key, *iv, /*strip_pkcs7=*/!probe_only);
        if (!plain || plain->size() < 4 || std::memcmp(plain->data(), kMagic, 4) != 0) continue;
        DescrambleResult res;
        res.scheme = "dlink_mh01";
        res.cipher = "AES-128-CBC";
        res.key_desc = "pw:" + std::string(pw).substr(0, 8) + "…";
        res.validated = "mh01";
        res.src_offset = off + kHdr + 16;
        res.src_len = ct.size();
        res.total_span = kHdr + paylen;
        if (!probe_only) res.data = std::move(*plain);
        return res;
    }
    return std::nullopt;
}

// ---- D-Link DLK: two 0x50-byte headers; the ciphertext is a series of
// `block_size` chunks, each a 16-byte IV + AES-256-CBC block keyed by the device
// passphrase used *directly* as the 32-byte key (no KDF). Ref: delink dlk.rs.
// Validated via a firmware magic (delink relies on padding only). PROVISIONAL. ----
std::optional<DescrambleResult> dlk(const Reader& r, size_t off, bool probe_only) {
    static constexpr uint8_t kMagic[3] = {'D', 'L', 'K'};
    constexpr size_t kHdr = 0x50, kIvSize = 16, kPad = 0x20, kBlkOff = 0x10, kSzOff = 0x2C;
    if (!starts_with(r, off, kMagic, 3)) return std::nullopt;
    auto sigsz = r.at<uint32_t>(off + kSzOff, Endian::Little);
    if (!sigsz) return std::nullopt;
    size_t h2 = off + kHdr + *sigsz;
    if (!starts_with(r, h2, kMagic, 3)) return std::nullopt;
    auto blkf = r.at<uint32_t>(h2 + kBlkOff, Endian::Little);
    auto totf = r.at<uint32_t>(h2 + kSzOff, Endian::Little);
    if (!blkf || !totf) return std::nullopt;
    size_t block_size = static_cast<size_t>(*blkf) + kPad, total = *totf;
    if (block_size <= kIvSize || total == 0) return std::nullopt;
    auto blob = r.bytes(h2 + kHdr, total);
    if (!blob) return std::nullopt;

    for (const char* pw : kDlinkDeviceKeys) {
        std::span<const uint8_t> key(reinterpret_cast<const uint8_t*>(pw), std::strlen(pw));
        if (key.size() != 32) continue;  // used directly as the AES-256 key
        std::vector<uint8_t> out;
        size_t processed = 0;
        bool ok = true;
        for (size_t p = 0; p < total; p += block_size) {
            size_t n = std::min(block_size, total - p);
            if (n <= kIvSize) { ok = false; break; }
            auto chunk = blob->subspan(p, n);
            auto dec = aes_cbc_decrypt(chunk.subspan(16), key, chunk.subspan(0, 16), true);
            if (!dec) { ok = false; break; }
            out.insert(out.end(), dec->begin(), dec->end());
            processed += n;
            if (probe_only) break;  // first block is enough to see the firmware magic
        }
        if (!ok || out.empty()) continue;
        if (!probe_only && processed != total) continue;
        const char* magic = firmware_magic({out.data(), out.size()});
        if (!*magic) continue;
        DescrambleResult res;
        res.scheme = "dlink_dlk";
        res.cipher = "AES-256-CBC";
        res.key_desc = "pw:" + std::string(pw).substr(0, 8) + "…";
        res.validated = magic;
        res.src_offset = h2 + kHdr;
        res.src_len = total;
        res.total_span = h2 + kHdr + total;
        if (!probe_only) res.data = std::move(out);
        return res;
    }
    return std::nullopt;
}

// ---- D-Link TLV (magic 64 80 19 40): the passphrase is HMAC-SHA1(board_id,
// model_name) as hex, over an OpenSSL Salted__ payload @0x74 (EVP_BytesToKey MD5,
// AES-256). Ref: delink tlv.rs. Validated via a firmware magic. PROVISIONAL. ----
std::optional<DescrambleResult> tlv(const Reader& r, size_t off, bool probe_only) {
    static constexpr uint8_t kMagic[4] = {0x64, 0x80, 0x19, 0x40};
    static constexpr uint8_t kSalted[8] = {'S', 'a', 'l', 't', 'e', 'd', '_', '_'};
    constexpr size_t kHdr = 0x74, kModelOff = 4, kBoardOff = 0x24, kStrMax = 0x20;
    if (!starts_with(r, off, kMagic, 4)) return std::nullopt;
    auto model = read_cstr(r, off + kModelOff, kStrMax);
    auto board = read_cstr(r, off + kBoardOff, kStrMax);
    if (model.empty() || board.empty()) return std::nullopt;
    auto hm = hmac_sha1(board, model);  // key = board_id, message = model_name
    std::string pw = to_hex(hm);
    std::span<const uint8_t> pass(reinterpret_cast<const uint8_t*>(pw.data()), pw.size());

    if (r.size() <= off + kHdr) return std::nullopt;
    auto payload = r.bytes(off + kHdr, r.size() - off - kHdr);
    if (!payload || payload->size() < 24 || std::memcmp(payload->data(), kSalted, 8) != 0)
        return std::nullopt;
    auto salt = payload->subspan(8, 8);
    size_t clen = payload->size() - 16;
    clen -= clen % 16;
    if (clen == 0) return std::nullopt;
    auto ki = evp_bytes_to_key(pass, salt, Hash::MD5, 32, 16);
    size_t take = probe_only ? std::min<size_t>(clen, 512) : clen;
    auto plain = aes_cbc_decrypt(payload->subspan(16, take), ki.key, ki.iv, /*strip_pkcs7=*/!probe_only);
    if (!plain) return std::nullopt;
    const char* magic = firmware_magic({plain->data(), plain->size()});
    if (!*magic) return std::nullopt;
    DescrambleResult res;
    res.scheme = "dlink_tlv";
    res.cipher = "AES-256-CBC";
    res.key_desc = "hmac-sha1(board,model)";
    res.validated = magic;
    res.src_offset = off + kHdr + 16;
    res.src_len = clen;
    res.total_span = kHdr + 16 + clen;
    if (!probe_only) res.data = std::move(*plain);
    return res;
}

// ---- EnGenius: keyless repeating-XOR. A 12-34-56-78-"all" pattern sits at
// header+0x5C; `length` (BE @0x20) is the total image size, the header ends at
// 136 + model_len (BE @0x84), and the payload is XORed with a fixed 8-byte key
// phase-anchored to where the key bytes appear in the file. Ref: unblob
// engeniustech/engenius.py. Plaintext is a FIT/uImage/squashfs. ----
std::optional<DescrambleResult> engenius(const Reader& r, size_t off, bool probe_only) {
    static constexpr uint8_t kPat[7] = {0x12, 0x34, 0x56, 0x78, 0x61, 0x6c, 0x6c};
    static constexpr uint8_t kKey[8] = {0xac, 0x78, 0x3c, 0x9e, 0xcf, 0x67, 0xb3, 0x59};
    if (!starts_with(r, off + 0x5C, kPat, 7)) return std::nullopt;
    auto length = r.at<uint32_t>(off + 0x20, Endian::Big);
    auto model_len = r.at<uint32_t>(off + 0x84, Endian::Big);
    if (!length || !model_len || *model_len > 256) return std::nullopt;
    size_t hdr_end = off + 136 + *model_len;
    size_t end = std::min<size_t>(off + *length, r.size());
    if (hdr_end >= end) return std::nullopt;

    // The XOR key appears verbatim in the file (a plaintext zero-run XORed with it);
    // that anchor sets the keystream phase. Search the image for it.
    auto data = r.data();
    auto it = std::search(data.begin(), data.end(), std::begin(kKey), std::end(kKey));
    if (it == data.end()) return std::nullopt;
    const int64_t ref = static_cast<int64_t>(it - data.begin());

    size_t take = probe_only ? std::min<size_t>(end - hdr_end, 512) : (end - hdr_end);
    auto ct = r.bytes(hdr_end, take);
    if (!ct) return std::nullopt;
    std::vector<uint8_t> out(take);
    for (size_t i = 0; i < take; ++i) {
        int64_t d = static_cast<int64_t>(hdr_end + i) - ref;  // may be negative
        out[i] = (*ct)[i] ^ kKey[static_cast<size_t>(((d % 8) + 8) % 8)];
    }
    const char* magic = firmware_magic({out.data(), out.size()});
    if (!*magic) return std::nullopt;

    DescrambleResult res;
    res.scheme = "engenius";
    res.cipher = "xor-8";
    res.key_desc = "fixed";
    res.validated = magic;
    res.src_offset = hdr_end;
    res.src_len = end - hdr_end;
    res.total_span = *length;
    if (!probe_only) res.data = std::move(out);
    return res;
}

// Cheap header-structure check (no crypto): does a scheme's header actually parse
// at `offset`? A bare magic match with no valid surrounding structure is a false
// positive (esp. DLK's 3-byte magic, which hits ~once per 16 MB of random data) —
// the `deobf` validator drops those instead of reporting an unkeyable finding.
// Returns {scheme, total_span} on a structural match.
struct StructMatch {
    const char* scheme;
    size_t span;
};
std::optional<StructMatch> scheme_structure(const Reader& r, size_t off) {
    static constexpr uint8_t kSalted[8] = {'S', 'a', 'l', 't', 'e', 'd', '_', '_'};
    auto u32le = [&](size_t o) { return r.at<uint32_t>(o, Endian::Little); };
    auto u32be = [&](size_t o) { return r.at<uint32_t>(o, Endian::Big); };

    // SHRS: magic + BE enc_size (bounded, %16) + IV + data offset present.
    if (starts_with(r, off, reinterpret_cast<const uint8_t*>("SHRS"), 4)) {
        auto enc = r.at<uint32_t>(off + 8, Endian::Big);
        if (enc && *enc > 0 && *enc % 16 == 0 && *enc <= (64u << 20) && r.bytes(off + 0x0C, 16) &&
            r.bytes(off + 0x6DC, 16))
            return StructMatch{"dlink_shrs", 0x6DC + *enc};
        return std::nullopt;
    }
    // encrpted_img: distinctive 12-byte magic + at least one block.
    if (starts_with(r, off, reinterpret_cast<const uint8_t*>("encrpted_img"), 12)) {
        if (r.size() > off + 16 + 16) return StructMatch{"dlink_encrpted_img", r.size() - off};
        return std::nullopt;
    }
    // openssl_salted: magic + salt + at least one block.
    if (starts_with(r, off, kSalted, 8)) {
        if (r.size() > off + 32) return StructMatch{"openssl_salted", r.size() - off};
        return std::nullopt;
    }
    // MH01: magic + a Salted__ payload at 0x41 (this is the real structural anchor).
    if (starts_with(r, off, reinterpret_cast<const uint8_t*>("MH01"), 4)) {
        if (starts_with(r, off + 0x41, kSalted, 8)) {
            auto enc = u32le(off + 0x18);
            if (enc && *enc >= 24) return StructMatch{"dlink_mh01", 0x41 + *enc};
        }
        return std::nullopt;
    }
    // DLK: two "DLK" headers (0x50 + signature_size apart). This is the fix — the
    // second header must be present, which a coincidental 3-byte "DLK" won't have.
    if (starts_with(r, off, reinterpret_cast<const uint8_t*>("DLK"), 3)) {
        auto sig = u32le(off + 0x2C);
        if (sig && *sig < (256u << 20) && starts_with(r, off + 0x50 + *sig,
                                                       reinterpret_cast<const uint8_t*>("DLK"), 3)) {
            auto tot = u32le(off + 0x50 + *sig + 0x2C);
            if (tot && *tot > 0) return StructMatch{"dlink_dlk", 0x50 + *sig + 0x50 + *tot};
        }
        return std::nullopt;
    }
    // TLV: magic + non-empty model/board strings + a Salted__ payload at 0x74.
    static constexpr uint8_t kTlv[4] = {0x64, 0x80, 0x19, 0x40};
    if (starts_with(r, off, kTlv, 4)) {
        if (starts_with(r, off + 0x74, kSalted, 8) && !read_cstr(r, off + 4, 0x20).empty() &&
            !read_cstr(r, off + 0x24, 0x20).empty())
            return StructMatch{"dlink_tlv", r.size() - off};
        return std::nullopt;
    }
    // EnGenius: the 12-34-56-78-"all" pattern at +0x5C + a plausible length/model_len.
    static constexpr uint8_t kEng[7] = {0x12, 0x34, 0x56, 0x78, 0x61, 0x6c, 0x6c};
    if (starts_with(r, off + 0x5C, kEng, 7)) {
        auto len = u32be(off + 0x20);
        auto ml = u32be(off + 0x84);
        if (len && *len > 136 && ml && *ml <= 256) return StructMatch{"engenius", *len};
        return std::nullopt;
    }
    return std::nullopt;
}

struct Entry {
    const char* name;
    SchemeFn fn;
};
constexpr std::array<Entry, 7> kSchemes = {{
    {"dlink_shrs", shrs},
    {"dlink_encrpted_img", encrpted_img},
    {"openssl_salted", openssl_salted},
    {"dlink_mh01", mh01},
    {"dlink_dlk", dlk},
    {"dlink_tlv", tlv},
    {"engenius", engenius},
}};

}  // namespace

std::optional<SchemeProbe> probe_scheme(const Reader& r, size_t offset) {
    // First: a scheme whose key actually decrypts the first block (verified).
    for (const auto& e : kSchemes) {
        if (auto res = e.fn(r, offset, /*probe_only=*/true)) {
            SchemeProbe p;
            p.scheme = res->scheme;
            p.cipher = res->cipher;
            p.total_span = res->total_span;
            p.validated = true;
            return p;
        }
    }
    // Else: a scheme whose header structure parses but no key in our table works.
    // A bare magic with no valid structure returns nothing here, so the validator
    // drops it (kills DLK-style 3-byte-magic false positives).
    if (auto sm = scheme_structure(r, offset)) {
        SchemeProbe p;
        p.scheme = sm->scheme;
        p.total_span = sm->span;
        p.validated = false;
        return p;
    }
    return std::nullopt;
}

std::optional<DescrambleResult> descramble(const Reader& r, size_t offset, const std::string& scheme) {
    for (const auto& e : kSchemes)
        if (scheme == e.name) return e.fn(r, offset, /*probe_only=*/false);
    return std::nullopt;
}

bool is_scheme(const std::string& name) {
    for (const auto& e : kSchemes)
        if (name == e.name) return true;
    return false;
}

}  // namespace ft

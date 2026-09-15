// luks.cpp — LUKS1 / LUKS2 encrypted-volume identifier. See luks.hpp.
#include "validators/luks.hpp"

#include <cctype>
#include <cstdint>
#include <string>

namespace ft {

namespace {

// A null-padded fixed-width ASCII field: bytes up to the first NUL, control and
// non-ASCII bytes dropped. Empty if the field is unreadable.
std::string ascii_field(const Reader& r, size_t off, size_t width) {
    auto b = r.bytes(off, width);
    if (!b) return {};
    std::string s;
    for (uint8_t c : *b) {
        if (c == 0) break;
        if (c >= 0x20 && c < 0x7f) s.push_back(static_cast<char>(c));
    }
    return s;
}

// A LUKS field value is a short token like "aes", "xts-plain64", "sha256",
// "argon2id" — lowercase letters/digits and a few punctuation chars.
bool token_ok(const std::string& s, size_t min_len = 1) {
    if (s.size() < min_len) return false;
    for (char c : s)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == ':' ||
              c == '.' || c == '+'))
            return false;
    return true;
}

// A LUKS UUID is the canonical 8-4-4-4-12 lowercase-hex form.
bool uuid_ok(const std::string& s) {
    if (s.size() != 36) return false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') return false;
        } else if (!std::isxdigit(static_cast<unsigned char>(s[i]))) {
            return false;
        }
    }
    return true;
}

uint16_t u16be(const Reader& r, size_t off) {
    auto v = r.at<uint16_t>(off, Endian::Big);
    return v ? *v : 0;
}
uint32_t u32be(const Reader& r, size_t off) {
    auto v = r.at<uint32_t>(off, Endian::Big);
    return v ? *v : 0;
}
uint64_t u64be(const Reader& r, size_t off) {
    auto v = r.at<uint64_t>(off, Endian::Big);
    return v ? *v : 0;
}

// Extract the string value of the first `"key":"value"` at or after `start`.
std::string json_str(const std::string& json, const std::string& key, size_t start = 0) {
    const std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat, start);
    if (p == std::string::npos) return {};
    p = json.find(':', p + pat.size());
    if (p == std::string::npos) return {};
    p = json.find('"', p);
    if (p == std::string::npos) return {};
    size_t e = json.find('"', p + 1);
    if (e == std::string::npos) return {};
    return json.substr(p + 1, e - (p + 1));
}

// Extract `"key":"value"` for the first occurrence at or after `anchor`. Used to
// read the KDF type from inside the "kdf":{...} object rather than matching the
// keyslot's own "type" earlier in the JSON.
std::string json_str_after(const std::string& json, const std::string& anchor,
                           const std::string& key) {
    size_t a = json.find(anchor);
    if (a == std::string::npos) return {};
    return json_str(json, key, a);
}

// Extract the integer value of the first `"key":<number>` occurrence.
long json_int(const std::string& json, const std::string& key) {
    const std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) return -1;
    p = json.find(':', p + pat.size());
    if (p == std::string::npos) return -1;
    ++p;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) ++p;
    long v = 0;
    bool any = false;
    while (p < json.size() && std::isdigit(static_cast<unsigned char>(json[p]))) {
        v = v * 10 + (json[p] - '0');
        any = true;
        ++p;
    }
    return any ? v : -1;
}

bool validate_luks1(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    std::string cipher = ascii_field(r, off + 0x08, 32);
    std::string mode = ascii_field(r, off + 0x28, 32);
    std::string hash = ascii_field(r, off + 0x48, 32);
    uint32_t payload_off = u32be(r, off + 0x68);  // sectors
    uint32_t key_bytes = u32be(r, off + 0x6C);
    std::string uuid = ascii_field(r, off + 0xA8, 40);

    if (!token_ok(cipher) || !token_ok(mode) || !token_ok(hash)) return false;
    if (key_bytes == 0 || key_bytes > 1024) return false;  // sane master-key length
    if (payload_off < 1 || payload_off > (1u << 24)) return false;
    if (!uuid_ok(uuid)) return false;

    Finding& out = ctx.out;
    out.type = "luks1";  // the version lives in the type (luks1 vs luks2)
    out.category = "encrypted";
    out.endian = Endian::Big;
    out.label = cipher + "-" + mode + ", " + hash + ", " + std::to_string(key_bytes * 8) + "-bit";
    out.set_confidence(Confidence::Consistent, "LUKS1 header: " + out.label + ", UUID " + uuid);
    return true;
}

bool validate_luks2(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t off = ctx.offset;

    uint64_t hdr_size = u64be(r, off + 0x08);
    std::string label = ascii_field(r, off + 0x18, 48);
    std::string csum_alg = ascii_field(r, off + 0x48, 32);
    std::string uuid = ascii_field(r, off + 0xA8, 40);
    uint64_t hdr_offset = u64be(r, off + 0x100);

    // LUKS2 header area is 16 KiB..4 MiB; the primary header sits at hdr_offset 0
    // (the secondary copy has a nonzero hdr_offset — reject it so one finding maps
    // the volume).
    if (hdr_size < 0x4000 || hdr_size > (4u << 20)) return false;
    if (hdr_offset != 0) return false;
    if (!uuid_ok(uuid)) return false;
    if (!csum_alg.empty() && !token_ok(csum_alg)) return false;

    // JSON metadata area: [off+4096, off+hdr_size). Bounded read, then pull the
    // cipher (segments[].encryption), KDF type, and key size out by field name.
    std::string cipher, kdf;
    long key_bits = -1;
    const uint64_t json_off = off + 0x1000;
    if (hdr_size > 0x1000) {
        size_t json_len = static_cast<size_t>(hdr_size - 0x1000);
        if (json_len > (1u << 20)) json_len = 1u << 20;  // cap
        if (auto jb = r.bytes(json_off, json_len)) {
            std::string json(reinterpret_cast<const char*>(jb->data()), jb->size());
            cipher = json_str(json, "encryption");
            kdf = json_str_after(json, "\"kdf\"", "type");  // KDF inside the keyslot's kdf object
            long ks = json_int(json, "key_size");  // bytes
            if (ks > 0 && ks <= 1024) key_bits = ks * 8;
        }
    }

    Finding& out = ctx.out;
    out.type = "luks2";  // the version lives in the type (luks1 vs luks2)
    out.category = "encrypted";
    out.endian = Endian::Big;
    std::string desc = cipher.empty() ? "encrypted" : cipher;
    if (!kdf.empty() && token_ok(kdf)) desc += ", " + kdf;
    if (key_bits > 0) desc += ", " + std::to_string(key_bits) + "-bit";
    out.label = desc;
    std::string ev = "LUKS2 header: " + desc + ", UUID " + uuid;
    if (!label.empty()) ev += ", label \"" + label + "\"";
    out.set_confidence(Confidence::Consistent, ev);
    return true;
}

}  // namespace

bool validate_luks(ValidatorCtx& ctx) {
    const uint16_t version = u16be(ctx.reader, ctx.offset + 6);
    if (version == 1) return validate_luks1(ctx);
    if (version == 2) return validate_luks2(ctx);
    return false;  // unknown LUKS version -> not identified
}

}  // namespace ft

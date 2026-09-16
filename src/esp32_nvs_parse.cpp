// esp32_nvs.cpp — ESP-IDF NVS shared parser. See esp32_nvs.hpp.
#include "esp32_nvs_parse.hpp"

#include <charconv>
#include <cstring>
#include <map>

#include "crc32.hpp"

namespace ft {

namespace {

constexpr size_t kPageSize = 4096;
constexpr size_t kEntriesPerPage = 126;
constexpr size_t kMaxPages = 4096;    // 16 MiB walk cap
constexpr size_t kMaxValues = 100000;
constexpr size_t kMaxReassembly = size_t(16) << 20;  // cap on one value's byte buffer

uint32_t u16(const Reader& r, size_t off) {
    auto v = r.at<uint16_t>(off, Endian::Little);
    return v ? *v : 0;
}
uint32_t u32(const Reader& r, size_t off) {
    auto v = r.at<uint32_t>(off, Endian::Little);
    return v ? *v : 0;
}

// 2-bit state of entry `i` from the page's bitmap (3=empty, 2=written, 0=erased).
uint8_t entry_state(const Reader& r, size_t page, size_t i) {
    auto b = r.at<uint8_t>(page + 32 + i / 4, Endian::Little);
    return b ? (*b >> (2 * (i % 4))) & 3 : 3;
}

std::string key_of(std::span<const uint8_t> e) {
    std::string s;
    for (size_t i = 8; i < 24; ++i) {
        if (e[i] == 0) break;
        if (e[i] < 0x20 || e[i] >= 0x7F) return "";  // not a printable key
        s.push_back(static_cast<char>(e[i]));
    }
    return s;
}

// python-style bytes repr: b'...' with \\, \t, \n, \r, \' and \xNN escapes.
std::string bytes_repr(std::span<const uint8_t> d) {
    std::string s = "b'";
    char hex[5];
    for (uint8_t c : d) {
        switch (c) {
            case '\\': s += "\\\\"; break;
            case '\'': s += "\\'"; break;
            case '\t': s += "\\t"; break;
            case '\n': s += "\\n"; break;
            case '\r': s += "\\r"; break;
            default:
                if (c >= 0x20 && c < 0x7F) {
                    s.push_back(static_cast<char>(c));
                } else {
                    std::snprintf(hex, sizeof(hex), "\\x%02x", c);
                    s += hex;
                }
        }
    }
    s.push_back('\'');
    return s;
}

// UTF-8 with invalid sequences replaced by U+FFFD (deterministic).
std::string utf8_lossy(std::span<const uint8_t> d) {
    std::string s;
    for (size_t i = 0; i < d.size();) {
        uint8_t c = d[i];
        size_t len = 0;
        if (c < 0x80) len = 1;
        else if ((c >> 5) == 0x6) len = 2;
        else if ((c >> 4) == 0xE) len = 3;
        else if ((c >> 3) == 0x1E) len = 4;
        bool valid = len && i + len <= d.size();
        for (size_t k = 1; valid && k < len; ++k) valid = (d[i + k] >> 6) == 0x2;
        if (valid && len > 1 && c == 0xC0) valid = false;  // overlong
        if (valid) {
            s.append(reinterpret_cast<const char*>(d.data() + i), len);
            i += len;
        } else {
            s += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return s;
}

std::string float_text(double v, bool is_double) {
    char buf[40];
    std::to_chars_result r;
    if (is_double)
        r = std::to_chars(buf, buf + sizeof(buf), v);
    else
        r = std::to_chars(buf, buf + sizeof(buf), static_cast<float>(v));
    std::string s(buf, r.ptr);
    if (s.find_first_of(".en") == std::string::npos) s += ".0";  // python repr style
    return s;
}

// One written entry's var-length payload: the raw bytes of its span-1
// continuation entries (padded to 32 each), truncated to `size`.
struct VarData {
    std::vector<uint8_t> bytes;
    uint32_t crc = 0;      // stored data crc (0 = none)
    bool crc_ok = false;
    bool complete = false;
};

bool read_span_data(const Reader& r, size_t page, size_t index, uint8_t span, uint16_t size,
                    VarData& out) {
    out.bytes.clear();
    out.complete = false;
    if (span < 1) return false;
    const size_t avail = static_cast<size_t>(span - 1) * 32;
    if (size > avail) return false;  // claimed bytes exceed the spanned entries
    out.bytes.reserve(size);
    for (size_t k = 1; k < span; ++k) {
        auto d = r.bytes(page + 64 + (index + k) * 32, 32);
        if (!d) return false;
        out.bytes.insert(out.bytes.end(), d->begin(), d->end());
    }
    out.bytes.resize(size);
    out.complete = true;
    return true;
}

bool is_upper(char c) { return c >= 'A' && c <= 'Z'; }

// Little-endian integer from raw bytes (host-endian independent).
uint64_t le_int(std::span<const uint8_t> d) {
    uint64_t v = 0;
    for (size_t k = 0; k < d.size(); ++k) v |= static_cast<uint64_t>(d[k]) << (8 * k);
    return v;
}

}  // namespace

uint32_t nvs_crc32(std::span<const uint8_t> data) { return crc32_raw(0, data) ^ 0xFFFFFFFFu; }

bool nvs_page_valid(const Reader& r, size_t off) {
    auto state = r.at<uint32_t>(off, Endian::Little);
    if (!state) return false;
    if (*state != 0xFFFFFFFEu && *state != 0xFFFFFFFCu && *state != 0xFFFFFFF8u) return false;
    auto ver = r.at<uint8_t>(off + 8, Endian::Little);
    if (!ver || (*ver != 0xFF && *ver != 0xFE)) return false;  // version 1 / 2
    auto unused = r.bytes(off + 9, 19);
    if (!unused) return false;
    for (uint8_t c : *unused)
        if (c != 0xFF) return false;
    auto crc = r.at<uint32_t>(off + 28, Endian::Little);
    auto body = r.bytes(off + 4, 24);
    if (!crc || !body) return false;
    return nvs_crc32(*body) == *crc;
}

bool nvs_page_erased(const Reader& r, size_t off) {
    auto d = r.bytes(off, kPageSize);
    if (!d) return false;
    for (uint8_t c : *d)
        if (c != 0xFF) return false;
    return true;
}

bool nvs_key_sensitive(const std::string& key) {
    static const char* kNeedles[] = {"password", "passwd", "token", "secret",
                                     "key",      "auth",   "credential"};
    std::string lower;
    lower.reserve(key.size());
    for (char c : key) lower.push_back(is_upper(c) ? static_cast<char>(c + 32) : c);
    for (const char* n : kNeedles)
        if (lower.find(n) != std::string::npos) return true;
    return false;
}

const char* nvs_type_name(uint8_t type) {
    switch (type) {
        case NVS_U8: return "uint8_t";
        case NVS_I8: return "int8_t";
        case NVS_U16: return "uint16_t";
        case NVS_I16: return "int16_t";
        case NVS_U32: return "uint32_t";
        case NVS_I32: return "int32_t";
        case NVS_U64: return "uint64_t";
        case NVS_I64: return "int64_t";
        case NVS_F32: return "float";
        case NVS_F64: return "double";
        case NVS_STR: return "string";
        case NVS_BLOB: return "blob";
        case NVS_BLOB_DATA: return "blob_data";
        case NVS_BLOB_IDX: return "blob_index";
        default: return nullptr;
    }
}

NvsParse nvs_parse(const Reader& r, size_t off) {
    NvsParse res;
    if (!nvs_page_valid(r, off)) return res;

    // Walk pages: CRC-valid pages carry data; erased pages are skipped but do
    // not end the partition (page hopping); anything else does.
    std::vector<size_t> pages;
    for (size_t p = 0; p < kMaxPages; ++p) {
        const size_t at = off + p * kPageSize;
        if (nvs_page_valid(r, at)) {
            pages.push_back(at);
            res.pages_valid++;
            res.extent = (at - off) + kPageSize;
        } else if (nvs_page_erased(r, at)) {
            res.pages_erased++;
        } else {
            break;
        }
        if (p + 1 == kMaxPages) res.capped = true;
    }
    res.ok = true;

    // Pass 1: namespace index -> name (ns=0 entries, u8 value).
    std::map<uint8_t, std::string> namespaces;
    for (size_t page : pages) {
        for (size_t i = 0; i < kEntriesPerPage; ++i) {
            if (entry_state(r, page, i) != 2) continue;
            auto e = r.bytes(page + 64 + i * 32, 32);
            if (!e) break;
            if ((*e)[0] == 0 && (*e)[1] == NVS_U8) {
                std::string name = key_of(*e);
                if (!name.empty()) namespaces[(*e)[24]] = name;
            }
        }
    }
    auto ns_name = [&](uint8_t idx) -> std::string {
        auto it = namespaces.find(idx);
        return it == namespaces.end() ? "#" + std::to_string(idx) : it->second;
    };

    // Pass 2: decode values; collect v2 blob chunks for reassembly.
    struct Pending {
        uint8_t ns;
        uint8_t chunk_start;
        uint8_t chunk_count;
        uint32_t size;
        std::string key;
    };
    struct Chunk {
        uint8_t ns, index;
        std::string key;
        VarData data;
        size_t order;
    };
    std::vector<Pending> pendings;
    std::vector<Chunk> chunks;
    size_t order = 0;

    auto warn = [&](std::string msg) {
        if (res.warnings.size() < 64) res.warnings.push_back(std::move(msg));
    };

    auto push_value = [&](uint8_t ns, std::string key, uint8_t type, std::string text) {
        if (res.values.size() >= kMaxValues) {
            res.capped = true;
            return;
        }
        NvsValue v;
        v.ns = ns_name(ns);
        v.key = std::move(key);
        v.type = type;
        v.text = std::move(text);
        v.sensitive = nvs_key_sensitive(v.key);
        res.values.push_back(std::move(v));
        res.keys++;
    };

    for (size_t page : pages) {
        for (size_t i = 0; i < kEntriesPerPage;) {
            if (entry_state(r, page, i) != 2) { ++i; continue; }
            auto eb = r.bytes(page + 64 + i * 32, 32);
            if (!eb) break;
            std::span<const uint8_t> e = *eb;
            const uint8_t ns = e[0], type = e[1], span = e[2], chunk = e[3];

            // Entry CRC covers everything except the CRC field itself.
            uint8_t crcbuf[28];
            std::memcpy(crcbuf, e.data(), 4);
            std::memcpy(crcbuf + 4, e.data() + 8, 24);
            uint32_t crc = u32(r, page + 64 + i * 32 + 4);
            bool bad = nvs_crc32(std::span<const uint8_t>(crcbuf, 28)) != crc;
            if (span < 1 || span > kEntriesPerPage - i) bad = true;
            const std::string key = key_of(e);
            if (key.empty()) bad = true;
            if (bad) {
                res.bad_entries++;
                ++i;
                continue;
            }
            const size_t data_off = page + 64 + i * 32 + 24;

            if (ns == 0) {  // namespace declaration (handled in pass 1)
                i += span;
                continue;
            }
            switch (type) {
                case NVS_U8: case NVS_I8: case NVS_U16: case NVS_I16:
                case NVS_U32: case NVS_I32: case NVS_U64: case NVS_I64: {
                    if (span != 1) { res.bad_entries++; break; }
                    const size_t sz = type & 0x0F;
                    auto d = r.bytes(data_off, sz);
                    if (!d) { res.bad_entries++; break; }
                    const uint64_t raw = le_int(*d);
                    if (type & 0x10) {
                        int64_t v = static_cast<int64_t>(raw << (8 - sz) * 8) >>
                                    ((8 - sz) * 8);  // sign-extend
                        push_value(ns, key, type, std::to_string(v));
                    } else {
                        push_value(ns, key, type, std::to_string(raw));
                    }
                    break;
                }
                case NVS_F32: case NVS_F64: {
                    if (span != 1) { res.bad_entries++; break; }
                    const size_t sz = type & 0x0F;
                    auto d = r.bytes(data_off, sz);
                    if (!d) { res.bad_entries++; break; }
                    double v = 0;
                    if (type == NVS_F32) {
                        const uint32_t bits = static_cast<uint32_t>(le_int(*d));
                        float f;
                        std::memcpy(&f, &bits, 4);
                        v = f;
                    } else {
                        const uint64_t bits = le_int(*d);
                        std::memcpy(&v, &bits, 8);
                    }
                    push_value(ns, key, type, float_text(v, type == NVS_F64));
                    break;
                }
                case NVS_STR: case NVS_BLOB: {
                    const uint16_t size = static_cast<uint16_t>(u16(r, data_off));
                    VarData vd;
                    vd.crc = u32(r, data_off + 4);
                    if (!read_span_data(r, page, i, span, size, vd)) {
                        res.bad_entries++;
                        warn("truncated value for key " + key);
                        break;
                    }
                    vd.crc_ok = nvs_crc32(vd.bytes) == vd.crc;
                    if (!vd.crc_ok) warn("data CRC mismatch for key " + key);
                    if (type == NVS_STR) {
                        auto b = vd.bytes;
                        while (!b.empty() && b.back() == 0) b.pop_back();
                        push_value(ns, key, type, utf8_lossy(b));
                    } else {
                        push_value(ns, key, type, bytes_repr(vd.bytes));
                    }
                    break;
                }
                case NVS_BLOB_IDX: {
                    Pending p;
                    p.ns = ns;
                    p.size = u32(r, data_off);
                    p.chunk_count = static_cast<uint8_t>(u16(r, data_off + 4) & 0xFF);
                    p.chunk_start = static_cast<uint8_t>(u16(r, data_off + 4) >> 8) & 0xFF;
                    p.key = key;
                    pendings.push_back(std::move(p));
                    break;
                }
                case NVS_BLOB_DATA: {
                    Chunk c;
                    c.ns = ns;
                    c.index = chunk;
                    c.key = key;
                    c.order = order++;
                    const uint16_t size = static_cast<uint16_t>(u16(r, data_off));
                    c.data.crc = u32(r, data_off + 4);
                    if (!read_span_data(r, page, i, span, size, c.data)) {
                        res.bad_entries++;
                        warn("truncated blob chunk for key " + key);
                        break;
                    }
                    c.data.crc_ok = nvs_crc32(c.data.bytes) == c.data.crc;
                    if (!c.data.crc_ok) warn("data CRC mismatch for chunk of key " + key);
                    chunks.push_back(std::move(c));
                    break;
                }
                default:
                    warn("unknown type 0x" + std::to_string(type) + " for key " + key);
                    break;
            }
            i += span;
        }
    }

    // Reassemble version-2 blobs: a blob_index plus its chunkCount blob_data
    // entries (chunkIndex runs from chunkStart).
    for (auto& p : pendings) {
        std::vector<uint8_t> blob;
        if (p.size <= kMaxReassembly) blob.reserve(p.size);
        size_t found = 0;
        for (uint32_t n = 0; n < p.chunk_count; ++n) {
            const uint8_t want = static_cast<uint8_t>(p.chunk_start + n);
            const Chunk* hit = nullptr;
            for (const auto& c : chunks) {
                if (c.ns == p.ns && c.key == p.key && c.index == want &&
                    (!hit || c.order < hit->order))
                    hit = &c;
            }
            if (!hit) break;
            found++;
            blob.insert(blob.end(), hit->data.bytes.begin(), hit->data.bytes.end());
            if (blob.size() > kMaxReassembly) break;
        }
        if (blob.size() > p.size) blob.resize(p.size);
        if (found != p.chunk_count)
            warn("blob " + p.key + ": " + std::to_string(found) + " of " +
                 std::to_string(p.chunk_count) + " chunks found");
        push_value(p.ns, p.key, NVS_BLOB, bytes_repr(blob));
    }
    // Chunks with no referencing blob_index: emit standalone.
    for (const auto& c : chunks) {
        bool referenced = false;
        for (const auto& p : pendings) {
            const int rel = static_cast<int>(c.index) - static_cast<int>(p.chunk_start);
            if (c.ns == p.ns && c.key == p.key && rel >= 0 && rel < p.chunk_count) {
                referenced = true;
                break;
            }
        }
        if (!referenced) push_value(c.ns, c.key, NVS_BLOB_DATA, bytes_repr(c.data.bytes));
    }
    return res;
}

}  // namespace ft

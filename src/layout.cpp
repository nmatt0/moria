#include "layout.hpp"

#include <stdexcept>

namespace ft {

namespace {

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Parse a "bytes[N]" / "skip[N]" bracket count. Returns width; throws on error.
uint32_t bracket_count(const std::string& tok, size_t lb) {
    size_t rb = tok.find(']', lb);
    if (rb == std::string::npos) throw std::runtime_error("layout: missing ']' in '" + tok + "'");
    std::string num = trim(tok.substr(lb + 1, rb - lb - 1));
    if (num.empty()) throw std::runtime_error("layout: empty count in '" + tok + "'");
    return static_cast<uint32_t>(std::stoul(num));
}

bool int_kind(const std::string& ty, Field::Kind& k, uint32_t& w) {
    if (ty == "u8")  { k = Field::U8;  w = 1; return true; }
    if (ty == "u16") { k = Field::U16; w = 2; return true; }
    if (ty == "u32") { k = Field::U32; w = 4; return true; }
    if (ty == "u64") { k = Field::U64; w = 8; return true; }
    if (ty == "i8")  { k = Field::I8;  w = 1; return true; }
    if (ty == "i16") { k = Field::I16; w = 2; return true; }
    if (ty == "i32") { k = Field::I32; w = 4; return true; }
    if (ty == "i64") { k = Field::I64; w = 8; return true; }
    return false;
}

// Sign-extend a raw little/big-decoded value of `width` bytes to uint64 bits.
uint64_t sign_extend(uint64_t v, uint32_t width) {
    uint32_t bits = width * 8;
    if (bits >= 64) return v;
    uint64_t sign = 1ull << (bits - 1);
    if (v & sign) v |= ~((1ull << bits) - 1);
    return v;
}

}  // namespace

Layout Layout::parse(const std::string& text) {
    Layout lay;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t semi = text.find(';', pos);
        std::string stmt = trim(text.substr(pos, semi == std::string::npos ? std::string::npos : semi - pos));
        pos = (semi == std::string::npos) ? text.size() : semi + 1;
        if (stmt.empty()) continue;

        Field f{};
        f.offset = lay.span;

        if (stmt.rfind("skip[", 0) == 0) {
            f.kind = Field::Skip;
            f.width = bracket_count(stmt, 4);
        } else if (stmt.rfind("bytes[", 0) == 0) {
            f.kind = Field::Bytes;
            f.width = bracket_count(stmt, 5);
            size_t rb = stmt.find(']');
            f.name = trim(stmt.substr(rb + 1));
        } else {
            // "<type> <name>"
            size_t sp = stmt.find_first_of(" \t");
            if (sp == std::string::npos)
                throw std::runtime_error("layout: expected '<type> <name>' in '" + stmt + "'");
            std::string ty = trim(stmt.substr(0, sp));
            f.name = trim(stmt.substr(sp + 1));
            if (!int_kind(ty, f.kind, f.width))
                throw std::runtime_error("layout: unknown type '" + ty + "'");
            if (f.name.empty())
                throw std::runtime_error("layout: missing field name after '" + ty + "'");
        }

        lay.span += f.width;
        lay.fields.push_back(std::move(f));
    }
    return lay;
}

std::optional<FieldMap> Layout::extract(const Reader& r, size_t base, Endian e) const {
    FieldMap out;
    out.reserve(fields.size());
    for (const auto& f : fields) {
        const size_t at = base + f.offset;
        switch (f.kind) {
            case Field::Skip:
            case Field::Bytes:
                if (!r.bytes(at, f.width)) return std::nullopt;
                break;
            case Field::U8:  { auto v = r.at<uint8_t>(at, e);  if (!v) return std::nullopt; out[f.name] = *v; break; }
            case Field::U16: { auto v = r.at<uint16_t>(at, e); if (!v) return std::nullopt; out[f.name] = *v; break; }
            case Field::U32: { auto v = r.at<uint32_t>(at, e); if (!v) return std::nullopt; out[f.name] = *v; break; }
            case Field::U64: { auto v = r.at<uint64_t>(at, e); if (!v) return std::nullopt; out[f.name] = *v; break; }
            case Field::I8:  { auto v = r.at<uint8_t>(at, e);  if (!v) return std::nullopt; out[f.name] = sign_extend(*v, 1); break; }
            case Field::I16: { auto v = r.at<uint16_t>(at, e); if (!v) return std::nullopt; out[f.name] = sign_extend(*v, 2); break; }
            case Field::I32: { auto v = r.at<uint32_t>(at, e); if (!v) return std::nullopt; out[f.name] = sign_extend(*v, 4); break; }
            case Field::I64: { auto v = r.at<uint64_t>(at, e); if (!v) return std::nullopt; out[f.name] = *v; break; }
        }
    }
    return out;
}

std::vector<std::string> Layout::int_field_names() const {
    std::vector<std::string> names;
    for (const auto& f : fields)
        if (f.kind != Field::Skip && f.kind != Field::Bytes) names.push_back(f.name);
    return names;
}

}  // namespace ft

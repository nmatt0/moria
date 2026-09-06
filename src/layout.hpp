// layout.hpp — declarative header struct language (phase2-design §3.3).
// A struct is a sequence of fields, e.g.:
//     u32 inodes;
//     u16 block_log;
//     bytes[32] name;
//     skip[8];
// Types: u8/u16/u32/u64, i8/i16/i32/i64, bytes[N] (named raw span, skipped for
// int extraction), skip[N] (anonymous padding). Endianness is supplied per hit.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "reader.hpp"

namespace ft {

using FieldMap = std::unordered_map<std::string, uint64_t>;

struct Field {
    enum Kind { U8, U16, U32, U64, I8, I16, I32, I64, Bytes, Skip } kind;
    std::string name;  // empty for skip
    uint32_t width;    // bytes
    size_t offset;     // from struct base
};

struct Layout {
    std::vector<Field> fields;
    size_t span = 0;  // total declared width

    bool empty() const { return fields.empty(); }

    // Parse struct text. Throws std::runtime_error on a malformed field.
    static Layout parse(const std::string& text);

    // Read every integer field at `base`. nullopt if any field runs past EOF.
    std::optional<FieldMap> extract(const Reader& r, size_t base, Endian e) const;

    // Names of integer fields (for load-time constraint validation).
    std::vector<std::string> int_field_names() const;
};

}  // namespace ft

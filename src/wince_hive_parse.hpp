// wince_hive_parse.hpp — value recovery from a Windows CE registry hive (.hv).
//
// A CE hive opens with a 0x400-byte block size, a zero DWORD, and the "EKIM"
// signature at offset 8, then a header of GUIDs and hashes before the cell
// data. The key tree is a CE-private cell layout that differs from NT's regf,
// so what is done here is RECOVERY, not a tree walk: every value record in the
// file is recovered structurally, without the key path it lived under.
//
// A value record is:
//   u16 type; u16 data_len; u16 name_len; char16 name[name_len]; u8 data[data_len]
//
// Recovery scans every 2-byte position and accepts a record only when the type
// is one of the seven CE uses, the declared lengths fit the file, the fixed
// widths for DWORD/QWORD agree, and the name decodes to a plausible registry
// value name. The scan never skips ahead past an accepted record, so one false
// positive cannot desynchronise the rest of the file.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "reader.hpp"

namespace ft {

struct CeHiveValue {
    size_t offset = 0;        // file offset of the record
    std::string name;         // UTF-8, converted from the stored UTF-16LE
    uint16_t type = 0;        // REG_SZ, REG_DWORD, ...
    std::string rendered;     // value as text: the string, the number, or hex
};

// Recover value records from the hive at `base`, appending to `out`, stopping
// at `limit` records. Returns the number recovered.
size_t ce_hive_values(const Reader& r, size_t base, std::vector<CeHiveValue>& out, size_t limit);

// Registry type name ("REG_SZ", ...), or "" for a type CE does not use.
const char* ce_hive_type_name(uint16_t type);

}  // namespace ft

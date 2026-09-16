// esp32_nvs.hpp — ESP-IDF NVS (non-volatile storage) shared parser (issue #18).
//
// An NVS partition is a log of 4 KiB pages. Page layout (all little-endian):
//   header (32):  u32 state, u32 seqno, u8 version (256 - n), 19 x 0xFF,
//                 u32 crc32 (over bytes 4..28)
//   entry state bitmap (32): 2 bits per entry x 126 entries (3=empty,
//                 2=written, 0=erased); the last 4 bits are unused (0xFF)
//   entries (126 x 32): u8 ns, u8 type, u8 span, u8 chunkIndex, u32 crc32,
//                 16-byte key, 8-byte data
// Small integers/floats are inline in data; strings and version-1 blobs span
// subsequent entries in the same page (span = total entries used); version-2
// blobs chunk across pages via a blob_index entry (0x48) + blob_data entries
// (0x42). Namespace entries (ns=0, u8 value) map namespace indexes to names.
// All CRCs are crc32(data) seeded with 0xFFFFFFFF (the zlib/ESP-ROM variant).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "reader.hpp"

namespace ft {

// NVS ItemType bytes (nvs_handle.hpp / nvs.h).
enum NvsType : uint8_t {
    NVS_U8 = 0x01, NVS_U16 = 0x02, NVS_U32 = 0x04, NVS_U64 = 0x08,
    NVS_I8 = 0x11, NVS_I16 = 0x12, NVS_I32 = 0x14, NVS_I64 = 0x18,
    NVS_STR = 0x21, NVS_F32 = 0x24, NVS_F64 = 0x28,
    NVS_BLOB = 0x41, NVS_BLOB_DATA = 0x42, NVS_BLOB_IDX = 0x48,
};

struct NvsValue {
    std::string ns;      // resolved namespace name ("#N" when undeclared)
    std::string key;
    uint8_t type = 0;    // NVS_STR / NVS_BLOB / ... (NVS_BLOB also for reassembled v2 blobs)
    std::string text;    // display form: decimal, float, UTF-8 string, or python-style b'...'
    bool sensitive = false;  // key matches the credential pattern
};

struct NvsParse {
    bool ok = false;         // page 0 is a valid NVS page
    size_t extent = 0;       // bytes from the start offset through the last valid page
    size_t pages_valid = 0;  // header-CRC-valid pages seen
    size_t pages_erased = 0;
    size_t keys = 0;         // values decoded
    size_t bad_entries = 0;  // written entries that failed CRC/span checks
    bool capped = false;     // a safety cap (pages / values) stopped the walk
    std::vector<NvsValue> values;
    std::vector<std::string> warnings;
};

// The NVS CRC variant: table CRC with init 0, final inversion
// (== zlib.crc32(data, 0xFFFFFFFF)).
uint32_t nvs_crc32(std::span<const uint8_t> data);

// True when the 32-byte page header at `off` is structurally valid AND its
// CRC verifies (state active/full/erasing, version byte, 0xFF padding).
bool nvs_page_valid(const Reader& r, size_t off);

// True when the whole 4 KiB page at `off` is erased flash (all 0xFF).
bool nvs_page_erased(const Reader& r, size_t off);

// Decode the NVS partition starting at `off`: walks pages while they are
// CRC-valid or erased (bounded), collects live (bitmap-written) entries,
// resolves namespaces, and reassembles string/blob values.
NvsParse nvs_parse(const Reader& r, size_t off);

// True when a key looks credential-bearing (password, passwd, token, secret,
// key, auth, credential — case-insensitive substring).
bool nvs_key_sensitive(const std::string& key);

const char* nvs_type_name(uint8_t type);

}  // namespace ft

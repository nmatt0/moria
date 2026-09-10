// cpio.cpp — cpio (newc/crc) extraction. See cpio.hpp.
//
// Format reference: the "new ASCII" (070701) and "new CRC" (070702) formats.
// Each entry is a 110-byte header of a 6-byte magic followed by thirteen
// 8-hex-digit fields, then the NUL-terminated name, then the file data; the
// name is padded so the data starts on a 4-byte boundary and the data is padded
// to a 4-byte boundary before the next header. The archive ends at a header
// whose name is "TRAILER!!!". All reads are range-checked through Reader; a bad
// size/namesize just ends the walk with a partial result.
#include "extract/cpio.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

// Unix mode field masks (c_mode is a full stat mode).
constexpr uint32_t S_IFMT_MASK = 0170000;
constexpr uint32_t S_IFDIR_V = 0040000;
constexpr uint32_t S_IFREG_V = 0100000;
constexpr uint32_t S_IFLNK_V = 0120000;

// Guardrails against hostile / corrupt archives.
constexpr size_t MAX_ENTRIES = 500000;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;  // 8 GiB per member

uint64_t align4(uint64_t x) { return (x + 3) & ~uint64_t(3); }

// Parse `n` ASCII hex digits at file offset `at`. nullopt if any is non-hex or
// out of range.
std::optional<uint64_t> hex_at(const Reader& r, size_t at, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        auto b = r.bytes(at + i, 1);
        if (!b) return std::nullopt;
        uint8_t c = (*b)[0];
        uint64_t d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return std::nullopt;
        v = v * 16 + d;
    }
    return v;
}

// Read exactly `n` bytes at `off` into a string (used for name and symlink
// target). Empty string if the range is out of bounds.
std::string read_bytes_str(const Reader& r, size_t off, size_t n) {
    auto b = r.bytes(off, n);
    if (!b) return {};
    return std::string(reinterpret_cast<const char*>(b->data()), n);
}

}  // namespace

bool extract_cpio(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out) {
    out.offset = f.offset;
    out.type = "cpio";
    out.root = subdir;

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    const size_t end = r.size();
    size_t pos = f.offset;
    bool saw_trailer = false;
    bool truncated = false;
    size_t entries = 0;

    while (pos + 110 <= end) {
        if (entries++ >= MAX_ENTRIES) { truncated = true; break; }

        auto magic = r.bytes(pos, 6);
        if (!magic) { truncated = true; break; }
        std::string m(reinterpret_cast<const char*>(magic->data()), 6);
        if (m != "070701" && m != "070702") { truncated = true; break; }

        auto c_mode = hex_at(r, pos + 14, 8);
        auto c_filesize = hex_at(r, pos + 54, 8);
        auto c_namesize = hex_at(r, pos + 94, 8);
        if (!c_mode || !c_filesize || !c_namesize || *c_namesize == 0) { truncated = true; break; }

        // Name (includes the trailing NUL); data starts on the next 4-byte
        // boundary after the 110-byte header + name.
        std::string name = read_bytes_str(r, pos + 110, *c_namesize);
        // Trim at the first NUL (namesize counts it).
        if (auto z = name.find('\0'); z != std::string::npos) name.resize(z);

        if (name == "TRAILER!!!") { saw_trailer = true; break; }

        const size_t data_off = pos + align4(110 + *c_namesize);
        const uint64_t fsize = *c_filesize;
        const size_t next = data_off + align4(fsize);
        // A member's data must lie within the file; otherwise stop with partial.
        if (fsize > MAX_FILE_BYTES || data_off > end || fsize > end - data_off) {
            truncated = true;
            break;
        }

        const uint32_t type = static_cast<uint32_t>(*c_mode) & S_IFMT_MASK;
        const uint32_t perm = static_cast<uint32_t>(*c_mode) & 0777;
        const bool named = !name.empty() && name != ".";
        const std::string rel = subdir + "/" + name;

        if (type == S_IFDIR_V) {
            if (named && root.make_dir(rel)) out.dirs++;
        } else if (type == S_IFLNK_V) {
            std::string target = read_bytes_str(r, data_off, static_cast<size_t>(fsize));
            if (auto z = target.find('\0'); z != std::string::npos) target.resize(z);
            if (named && !target.empty() && root.make_symlink(rel, target))
                out.symlinks++;
        } else if (type == S_IFREG_V) {
            auto b = r.bytes(data_off, static_cast<size_t>(fsize));
            if (named && b) {
                std::vector<uint8_t> data(b->begin(), b->end());
                if (root.write_file(rel, data, perm)) {
                    out.files++;
                    out.bytes += data.size();
                } else {
                    out.warnings.push_back("write failed: " + name);
                }
            }
        }
        // Other types (fifo/chr/blk/sock): skipped (counted by omission).

        if (next <= pos) { truncated = true; break; }  // no forward progress
        pos = next;
    }

    if (!saw_trailer) {
        truncated = true;
        out.warnings.push_back("end marker not found; archive may be incomplete");
    }
    out.status = truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

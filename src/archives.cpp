#include "archives.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ft {

namespace {

uint64_t align4(uint64_t x) { return (x + 3) & ~uint64_t(3); }
uint64_t align512(uint64_t x) { return (x + 511) & ~uint64_t(511); }  // tar record size

// Read a NUL-terminated (or fixed-max) string at `off`, up to `max` bytes.
std::string read_cstr(const Reader& r, size_t off, size_t max) {
    std::string s;
    for (size_t i = 0; i < max; ++i) {
        auto b = r.bytes(off + i, 1);
        if (!b) break;
        uint8_t c = (*b)[0];
        if (c == 0) break;
        s += static_cast<char>(c);
    }
    return s;
}

// Parse `n` octal digits at `off` (tar size field). Skips leading spaces/NULs.
uint64_t octal_at(const Reader& r, size_t off, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        auto b = r.bytes(off + i, 1);
        if (!b) break;
        uint8_t c = (*b)[0];
        if (c == ' ' || c == 0) continue;
        if (c < '0' || c > '7') break;
        v = v * 8 + (c - '0');
    }
    return v;
}

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

void list_tar(const Reader& r, Finding& f) {
    size_t pos = f.offset;
    const size_t end = r.size();
    while (pos + 512 <= end) {
        auto name0 = r.bytes(pos, 1);
        if (!name0 || (*name0)[0] == 0) break;  // zero block => end of archive
        std::string name = read_cstr(r, pos, 100);
        uint64_t size = octal_at(r, pos + 124, 11);
        if (!name.empty()) {
            if (f.members.size() >= MAX_MEMBERS) { f.members_truncated = true; break; }
            f.members.push_back({name, size, "", {}});
        }
        pos += 512 + align512(size);
    }
}

void list_cpio(const Reader& r, Finding& f) {
    size_t pos = f.offset;
    const size_t end = r.size();
    while (pos + 110 <= end) {
        auto magic = r.bytes(pos, 6);
        if (!magic) break;
        std::string m(reinterpret_cast<const char*>(magic->data()), 6);
        if (m != "070701" && m != "070702") break;
        auto filesize = hex_at(r, pos + 6 + 6 * 8, 8);
        auto namesize = hex_at(r, pos + 6 + 11 * 8, 8);
        if (!filesize || !namesize || *namesize == 0) break;
        std::string name = read_cstr(r, pos + 110, *namesize);
        if (name == "TRAILER!!!") break;
        if (!name.empty()) {
            if (f.members.size() >= MAX_MEMBERS) { f.members_truncated = true; break; }
            f.members.push_back({name, static_cast<size_t>(*filesize), "", {}});
        }
        pos += align4(110 + *namesize) + align4(*filesize);
    }
}

void list_zip(const Reader& r, Finding& f) {
    const size_t base = f.offset;
    const size_t filesz = r.size();
    static const std::vector<uint8_t> EOCD = {0x50, 0x4B, 0x05, 0x06};
    size_t window = (filesz > 66000) ? filesz - 66000 : base;
    size_t eocd = 0;
    bool found = false;
    for (size_t i = window; i + 22 <= filesz; ++i)
        if (r.matches_at(i, EOCD)) { eocd = i; found = true; }
    if (!found) return;

    auto cd_offset = r.at<uint32_t>(eocd + 16, Endian::Little);
    if (!cd_offset) return;
    size_t pos = base + *cd_offset;
    static const std::vector<uint8_t> CDH = {0x50, 0x4B, 0x01, 0x02};
    while (pos + 46 <= filesz && r.matches_at(pos, CDH)) {
        auto uncomp = r.at<uint32_t>(pos + 24, Endian::Little);
        auto namelen = r.at<uint16_t>(pos + 28, Endian::Little);
        auto extralen = r.at<uint16_t>(pos + 30, Endian::Little);
        auto commentlen = r.at<uint16_t>(pos + 32, Endian::Little);
        if (!uncomp || !namelen || !extralen || !commentlen) break;
        std::string name = read_cstr(r, pos + 46, *namelen);
        if (!name.empty()) {
            if (f.members.size() >= MAX_MEMBERS) { f.members_truncated = true; break; }
            f.members.push_back({name, static_cast<size_t>(*uncomp), "", {}});
        }
        pos += 46 + *namelen + *extralen + *commentlen;
    }
}

}  // namespace

void list_members(const Reader& r, Finding& f) {
    if (f.type == "tar") list_tar(r, f);
    else if (f.type == "cpio") list_cpio(r, f);
    else if (f.type == "zip") list_zip(r, f);
}

}  // namespace ft

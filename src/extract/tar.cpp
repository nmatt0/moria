// tar.cpp — POSIX tar (ustar) extraction. See tar.hpp.
//
// Each entry is a 512-byte header followed by the file data padded to 512 bytes.
// Header fields used: name@0(100), mode@100(8 octal), size@124(12 octal),
// chksum@148(8 octal), typeflag@156(1), linkname@157(100), magic@257("ustar"),
// prefix@345(155). The stored checksum (header summed with the chksum field read
// as spaces) gates a real header, so the zero-block terminator or trailing
// garbage ends the walk. GNU 'L' long-name records set the next entry's name;
// pax 'x'/'g' headers are skipped. All reads are range-checked through Reader.
#include "extract/tar.hpp"

#include <cstdint>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr size_t BLOCK = 512;
constexpr size_t MAX_ENTRIES = 2000000;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;

uint64_t align512(uint64_t x) { return (x + 511) & ~uint64_t(511); }

std::string read_cstr(const Reader& r, size_t off, size_t max) {
    std::string s;
    for (size_t i = 0; i < max; ++i) {
        auto b = r.bytes(off + i, 1);
        if (!b || (*b)[0] == 0) break;
        s += static_cast<char>((*b)[0]);
    }
    return s;
}

// Parse an octal field of `n` bytes (leading spaces/NULs skipped, stops at the
// first space/NUL/non-octal). tar stores sizes and modes this way.
uint64_t octal_at(const Reader& r, size_t off, size_t n) {
    uint64_t v = 0;
    bool started = false;
    for (size_t i = 0; i < n; ++i) {
        auto b = r.bytes(off + i, 1);
        if (!b) break;
        uint8_t c = (*b)[0];
        if (c == ' ' || c == 0) {
            if (started) break;
            continue;
        }
        if (c < '0' || c > '7') break;
        v = v * 8 + (c - '0');
        started = true;
    }
    return v;
}

// True if the 512-byte header at `off` has a valid stored checksum.
bool checksum_ok(const Reader& r, size_t off) {
    auto hdr = r.bytes(off, BLOCK);
    if (!hdr) return false;
    uint64_t stored = octal_at(r, off + 148, 8);
    uint64_t sum = 0;
    for (size_t i = 0; i < BLOCK; ++i)
        sum += (i >= 148 && i < 156) ? ' ' : (*hdr)[i];  // chksum field read as spaces
    return sum == stored;
}

// Parse a pax extended header's records ("<len> key=value\n" sequence) at
// `off`..`off+size`, returning the value for `key` if present.
std::string pax_value(const Reader& r, size_t off, uint64_t size, const std::string& key) {
    auto span = r.bytes(off, static_cast<size_t>(size));
    if (!span) return {};
    std::string s(reinterpret_cast<const char*>(span->data()), static_cast<size_t>(size));
    size_t p = 0;
    while (p < s.size()) {
        size_t sp = s.find(' ', p);
        if (sp == std::string::npos) break;
        uint64_t reclen = 0;
        for (size_t i = p; i < sp; ++i) {
            if (s[i] < '0' || s[i] > '9') { reclen = 0; break; }
            reclen = reclen * 10 + (s[i] - '0');
        }
        if (reclen < (sp - p) + 2 || p + reclen > s.size()) break;
        std::string rec = s.substr(sp + 1, reclen - (sp - p) - 2);  // "key=value"
        size_t eq = rec.find('=');
        if (eq != std::string::npos && rec.substr(0, eq) == key) return rec.substr(eq + 1);
        p += reclen;
    }
    return {};
}

}  // namespace

bool extract_tar(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.offset = f.offset;
    out.type = "tar";
    out.root = subdir;
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    const size_t end = r.size();
    size_t pos = f.offset;
    bool truncated = false;
    size_t entries = 0;
    std::string long_name;      // pending GNU 'L' long name for the next entry
    std::string pax_path;       // pending pax "path=" for the next entry
    std::string pax_linkpath;   // pending pax "linkpath=" for the next entry

    while (pos + BLOCK <= end) {
        if (entries++ > MAX_ENTRIES) { truncated = true; break; }
        auto first = r.bytes(pos, 1);
        if (!first) break;
        if ((*first)[0] == 0) break;  // zero block => end of archive
        if (!checksum_ok(r, pos)) break;  // not a valid header (garbage/end)

        const uint64_t size = octal_at(r, pos + 124, 12);
        auto tf = r.bytes(pos + 156, 1);
        char typeflag = tf ? static_cast<char>((*tf)[0]) : '0';
        const size_t data_off = pos + BLOCK;
        const uint64_t padded = align512(size);
        if (size > MAX_FILE_BYTES || data_off > end || padded > end - data_off) {
            truncated = true;
            break;
        }

        if (typeflag == 'L') {  // GNU long name: data is the name for the next entry
            long_name = read_cstr(r, data_off, static_cast<size_t>(size));
            pos = data_off + padded;
            continue;
        }
        if (typeflag == 'x') {  // pax extended header: path=/linkpath= for the next entry
            std::string p = pax_value(r, data_off, size, "path");
            std::string lp = pax_value(r, data_off, size, "linkpath");
            if (!p.empty()) pax_path = p;
            if (!lp.empty()) pax_linkpath = lp;
            pos = data_off + padded;
            continue;
        }
        if (typeflag == 'g' || typeflag == 'K') {  // global pax / GNU long link: skip
            pos = data_off + padded;
            continue;
        }

        // Build the member path: pax path, else GNU long name, else prefix + "/" + name.
        std::string name = !pax_path.empty() ? pax_path : long_name;
        long_name.clear();
        std::string pax_link = pax_linkpath;
        pax_path.clear();
        pax_linkpath.clear();
        if (name.empty()) {
            std::string prefix = read_cstr(r, pos + 345, 155);
            name = read_cstr(r, pos, 100);
            if (!prefix.empty() && !name.empty()) name = prefix + "/" + name;
        }

        if (!name.empty() && name != "." && name != "./" &&
            name.find('\0') == std::string::npos) {
            const std::string full = subdir + "/" + name;
            const uint32_t mode = static_cast<uint32_t>(octal_at(r, pos + 100, 8)) & 0777;
            if (typeflag == '5') {  // directory
                if (root.make_dir(full)) out.dirs++;
            } else if (typeflag == '2') {  // symlink
                std::string target = !pax_link.empty() ? pax_link : read_cstr(r, pos + 157, 100);
                if (!target.empty() && root.make_symlink(full, target)) out.symlinks++;
            } else if (typeflag == '0' || typeflag == '\0' || typeflag == '7') {  // regular
                auto d = r.bytes(data_off, static_cast<size_t>(size));
                if (d) {
                    std::vector<uint8_t> data(d->begin(), d->end());
                    if (root.write_file(full, data, mode)) {
                        out.files++;
                        out.bytes += data.size();
                    } else {
                        out.warnings.push_back("write failed: " + name);
                    }
                }
            }
            // hardlink ('1'), char/block/fifo: skipped.
        }

        pos = data_off + padded;
    }

    out.status = truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

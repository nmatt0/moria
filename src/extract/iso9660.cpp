// iso9660.cpp — ISO 9660 extraction. See iso9660.hpp.
#include "extract/iso9660.hpp"

#include <algorithm>
#include <cstdint>
#include <cctype>
#include <cstring>
#include <span>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint64_t PVD_OFFSET = 32768;  // sector 16
constexpr uint8_t FLAG_DIR = 0x02;
constexpr uint8_t FLAG_MULTI = 0x80;

constexpr size_t MAX_DEPTH = 128;
constexpr size_t MAX_RECORDS = 4000000;
constexpr uint64_t MAX_FILE_BYTES = uint64_t(8) << 30;
constexpr int MAX_CE = 32;  // continuation-area follow limit

std::optional<uint32_t> u32le(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Little); }
std::optional<uint16_t> u16le(const Reader& r, uint64_t o) { return r.at<uint16_t>(o, Endian::Little); }

struct Ctx {
    const Reader& r;
    uint64_t base;
    uint32_t block_size;
    SafeRoot& root;
    std::string subdir;
    Extracted& out;
    bool truncated = false;
    size_t records = 0;
    std::set<uint32_t> dir_stack{};
};

// A parsed directory record's Rock Ridge fields.
struct RockRidge {
    std::string name;      // NM (may be empty)
    std::string symlink;   // SL target (may be empty)
    bool is_symlink = false;
};

// Assemble the full System Use area (inline + CE continuations) then decode the
// Rock Ridge NM / SL entries.
RockRidge parse_rock_ridge(Ctx& c, std::span<const uint8_t> inline_su) {
    RockRidge rr;
    std::vector<uint8_t> su(inline_su.begin(), inline_su.end());
    int ce_follows = 0;
    size_t p = 0;
    while (p + 4 <= su.size()) {
        const uint8_t* e = su.data() + p;
        const uint8_t len = e[2];
        if (len < 4 || p + len > su.size()) break;
        if (e[0] == 'N' && e[1] == 'M') {
            // NM: flags@4 (bit0 CONTINUE), name@5..len
            if (len > 5 && !(e[4] & 0x06))  // ignore CURRENT/PARENT markers
                rr.name.append(reinterpret_cast<const char*>(e + 5), len - 5);
        } else if (e[0] == 'S' && e[1] == 'L') {
            // SL: flags@4, then component records {flags,len,content}
            rr.is_symlink = true;
            size_t q = 5;
            while (q + 2 <= static_cast<size_t>(len)) {
                const uint8_t cflags = e[q];
                const uint8_t clen = e[q + 1];
                if (q + 2 + clen > static_cast<size_t>(len)) break;
                if (cflags & 0x08) {  // ROOT
                    if (rr.symlink.empty()) rr.symlink = "/";
                } else if (cflags & 0x02) {  // CURRENT "."
                    rr.symlink += ".";
                } else if (cflags & 0x04) {  // PARENT ".."
                    rr.symlink += "..";
                } else {
                    rr.symlink.append(reinterpret_cast<const char*>(e + q + 2), clen);
                }
                if (!(cflags & 0x01)) {  // not CONTINUE: end of this component
                    // separator unless this was the last component (handled by caller trim)
                    rr.symlink += "/";
                }
                q += 2 + clen;
            }
        } else if (e[0] == 'C' && e[1] == 'E' && len >= 28 && ce_follows < MAX_CE) {
            // Continuation: block@4 (LE), offset@12 (LE), length@20 (LE).
            ++ce_follows;
            uint32_t ce_block, ce_off, ce_len;
            std::memcpy(&ce_block, e + 4, 4);
            std::memcpy(&ce_off, e + 12, 4);
            std::memcpy(&ce_len, e + 20, 4);
            const uint64_t abs = c.base + uint64_t(ce_block) * c.block_size + ce_off;
            if (ce_len > 0 && ce_len <= 8192) {
                if (auto d = c.r.bytes(static_cast<size_t>(abs), ce_len)) {
                    // Continue parsing from the appended data.
                    su.insert(su.end(), d->begin(), d->end());
                }
            }
        }
        p += len;
    }
    if (rr.is_symlink && !rr.symlink.empty() && rr.symlink.back() == '/')
        rr.symlink.pop_back();
    return rr;
}

// ISO name without the ";version" suffix and trailing dot.
std::string clean_iso_name(std::span<const uint8_t> raw) {
    std::string n(raw.begin(), raw.end());
    if (auto s = n.find(';'); s != std::string::npos) n.resize(s);
    if (!n.empty() && n.back() == '.') n.pop_back();
    for (auto& ch : n) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return n;
}

void walk(Ctx& c, uint32_t lba, uint32_t length, const std::string& rel, size_t depth);

void walk(Ctx& c, uint32_t lba, uint32_t length, const std::string& rel, size_t depth) {
    if (depth > MAX_DEPTH) { c.truncated = true; return; }
    auto dir = c.r.bytes(static_cast<size_t>(c.base + uint64_t(lba) * c.block_size), length);
    if (!dir) { c.truncated = true; return; }
    const uint8_t* d = dir->data();

    size_t o = 0;
    while (o + 33 <= length) {
        if (c.records++ > MAX_RECORDS) { c.truncated = true; return; }
        const uint8_t rl = d[o];
        if (rl == 0) {
            // Advance to the next logical block boundary.
            const size_t next = ((o / c.block_size) + 1) * c.block_size;
            if (next <= o) break;
            o = next;
            continue;
        }
        if (o + rl > length || rl < 33) break;
        const uint8_t ext_attr = d[o + 1];
        uint32_t extent, data_len;
        std::memcpy(&extent, d + o + 2, 4);
        std::memcpy(&data_len, d + o + 10, 4);
        const uint8_t flags = d[o + 25];
        const uint8_t nlen = d[o + 32];
        if (o + 33 + nlen > length) break;
        std::span<const uint8_t> raw_name(d + o + 33, nlen);

        // "." (0x00) and ".." (0x01) records.
        const bool dot = nlen == 1 && (raw_name[0] == 0x00 || raw_name[0] == 0x01);
        if (dot) { o += rl; continue; }

        // System Use area (Rock Ridge) after the name, padded to even.
        const size_t su_start = o + 33 + nlen + (1 - (nlen & 1));
        std::span<const uint8_t> su;
        if (su_start < o + rl) su = std::span<const uint8_t>(d + su_start, (o + rl) - su_start);
        RockRidge rr = parse_rock_ridge(c, su);

        std::string name = !rr.name.empty() ? rr.name : clean_iso_name(raw_name);
        if (name.empty() || name == "." || name == ".." || name.find('/') != std::string::npos) {
            o += rl;
            continue;
        }
        const std::string child_rel = rel.empty() ? name : rel + "/" + name;
        const std::string full = c.subdir + "/" + child_rel;
        const uint64_t data_off = c.base + uint64_t(extent + ext_attr) * c.block_size;

        if (rr.is_symlink) {
            if (!rr.symlink.empty() && c.root.make_symlink(full, rr.symlink)) c.out.symlinks++;
        } else if (flags & FLAG_DIR) {
            if (!c.dir_stack.insert(extent).second) { o += rl; continue; }  // cycle guard
            if (c.root.make_dir(full)) c.out.dirs++;
            walk(c, extent, data_len, child_rel, depth + 1);
            c.dir_stack.erase(extent);
        } else {
            if (flags & FLAG_MULTI) c.truncated = true;  // multi-extent not reassembled
            uint64_t want = std::min<uint64_t>(data_len, MAX_FILE_BYTES);
            std::vector<uint8_t> data;
            if (want > 0) {
                auto b = c.r.bytes(static_cast<size_t>(data_off), static_cast<size_t>(want));
                if (!b) { c.truncated = true; o += rl; continue; }
                data.assign(b->begin(), b->end());
            }
            if (c.root.write_file(full, data, 0644)) {
                c.out.files++;
                c.out.bytes += data.size();
            } else {
                c.out.warnings.push_back("write failed: " + child_rel);
            }
        }
        o += rl;
    }
}

}  // namespace

bool extract_iso9660(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                     Extracted& out) {
    out.offset = f.offset;
    out.type = "iso9660";
    out.root = subdir;
    const uint64_t base = f.offset;

    // Primary Volume Descriptor at sector 16.
    auto id = r.bytes(base + PVD_OFFSET + 1, 5);
    if (!id || std::string(id->begin(), id->end()) != "CD001") {
        out.status = "error:no-pvd";
        return true;
    }
    auto bs = u16le(r, base + PVD_OFFSET + 128);  // logical block size (LE half)
    if (!bs || *bs < 512 || (*bs & (*bs - 1))) {
        out.status = "error:bad-pvd";
        return true;
    }
    // Root directory record at PVD+156.
    const uint64_t rr_off = base + PVD_OFFSET + 156;
    auto root_lba = u32le(r, rr_off + 2);
    auto root_len = u32le(r, rr_off + 10);
    if (!root_lba || !root_len) {
        out.status = "error:bad-pvd";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    Ctx c{r, base, *bs, root, subdir, out};
    walk(c, *root_lba, *root_len, "", 0);
    out.status = c.truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

// fit.cpp — U-Boot FIT (Flattened Image Tree) extraction. See fit.hpp.
//
// A FIT is an FDT (device-tree) blob. Header @off (big-endian, 40 bytes):
//   magic@0, totalsize@4, off_dt_struct@8, off_dt_strings@12, off_mem_rsvmap@16,
//   version@20, last_comp_version@24, boot_cpuid_phys@28, size_dt_strings@32,
//   size_dt_struct@36. The struct block (at off+off_dt_struct) is a stream of
//   big-endian u32 tokens: BEGIN_NODE(1)+name, END_NODE(2), PROP(3)+len+nameoff+
//   value, NOP(4), END(9). Property names are NUL-terminated strings in the
//   strings block (off+off_dt_strings + nameoff).
//
// The root node has an `images` subnode; each of ITS subnodes is one subimage
// (kernel/ramdisk/fdt/...). A subimage payload is either embedded in a `data`
// property or external: `data-offset`+`data-size` (offset relative to the
// aligned end of the FDT structure) or `data-position`+`data-size` (absolute
// from the FIT start). We split each payload out and decompress per its
// `compression` property. Range-checked throughout via Reader; writes via SafeRoot.
#include "extract/fit.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "extract/decompress.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint32_t FDT_MAGIC = 0xd00dfeed;
constexpr uint32_t FDT_BEGIN_NODE = 1;
constexpr uint32_t FDT_END_NODE = 2;
constexpr uint32_t FDT_PROP = 3;
constexpr uint32_t FDT_NOP = 4;
constexpr uint32_t FDT_END = 9;

constexpr size_t MAX_TOKENS = 4u << 20;       // struct-walk iteration cap
constexpr size_t MAX_SUBIMAGES = 4096;        // sane cap on /images children
constexpr uint64_t MAX_PAYLOAD = uint64_t(1) << 30;  // per-subimage byte cap

std::optional<uint32_t> be32(const Reader& r, uint64_t o) {
    return r.at<uint32_t>(o, Endian::Big);
}

inline uint64_t align4(uint64_t v) { return (v + 3) & ~uint64_t(3); }

// The parsed FDT geometry (all absolute file offsets).
struct Fdt {
    uint64_t totalsize = 0;
    uint64_t struct_off = 0;   // absolute
    uint64_t struct_end = 0;   // absolute, bounded
    uint64_t strings_off = 0;  // absolute
    uint64_t strings_end = 0;  // absolute
};

std::optional<Fdt> parse_header(const Reader& r, uint64_t off) {
    auto magic = be32(r, off);
    if (!magic || *magic != FDT_MAGIC) return std::nullopt;
    auto totalsize = be32(r, off + 4);
    auto off_struct = be32(r, off + 8);
    auto off_strings = be32(r, off + 12);
    auto size_strings = be32(r, off + 32);
    auto size_struct = be32(r, off + 36);
    if (!totalsize || !off_struct || !off_strings || !size_strings || !size_struct)
        return std::nullopt;
    Fdt f;
    f.totalsize = *totalsize;
    f.struct_off = off + *off_struct;
    f.strings_off = off + *off_strings;
    // Bound the struct/strings regions to what the header claims and the file holds.
    uint64_t end = off + f.totalsize;
    if (end > r.size()) end = r.size();
    f.struct_end = f.struct_off + *size_struct;
    if (f.struct_end > end) f.struct_end = end;
    f.strings_end = f.strings_off + *size_strings;
    if (f.strings_end > end) f.strings_end = end;
    if (f.struct_off >= r.size() || f.struct_off > f.struct_end) return std::nullopt;
    return f;
}

// Read a NUL-terminated node/prop name starting at absolute `pos`, capped at
// `end`. Sets `next` to the position just past the terminator.
std::string read_cstr(const Reader& r, uint64_t pos, uint64_t end, uint64_t& next) {
    std::string s;
    while (pos < end) {
        auto b = r.bytes(pos, 1);
        if (!b) break;
        char c = static_cast<char>((*b)[0]);
        ++pos;
        if (c == '\0') break;
        s.push_back(c);
        if (s.size() > 4096) break;  // runaway guard
    }
    next = pos;
    return s;
}

// A collected /images subimage node.
struct Sub {
    std::string name;
    std::string comp = "none";
    std::string type;
    bool has_data = false;
    uint64_t data_off = 0, data_len = 0;  // embedded `data` value (absolute file offset)
    bool has_ext_off = false;
    uint64_t ext_off = 0;  // `data-offset` (relative to aligned struct end)
    bool has_ext_pos = false;
    uint64_t ext_pos = 0;  // `data-position` (absolute from FIT start)
    bool has_ext_size = false;
    uint64_t ext_size = 0;  // `data-size`
};

Compressor comp_of(const std::string& c) {
    if (c == "gzip") return Compressor::Gzip;
    if (c == "lzma") return Compressor::Lzma;   // FIT lzma = .lzma "alone" stream
    if (c == "lz4") return Compressor::Lz4;      // lz4 frame
    if (c == "zstd") return Compressor::Zstd;
    return Compressor::Unknown;                   // none / bzip2 / lzo / unknown
}

// Resolve a subimage's raw (compressed or stored) payload bytes.
std::optional<std::vector<uint8_t>> raw_payload(const Reader& r, uint64_t fit_off, const Fdt& fdt,
                                                const Sub& s) {
    uint64_t abs = 0, len = 0;
    if (s.has_data) {
        abs = s.data_off;
        len = s.data_len;
    } else if (s.has_ext_pos && s.has_ext_size) {
        abs = fit_off + s.ext_pos;  // data-position is relative to the FIT start
        len = s.ext_size;
    } else if (s.has_ext_off && s.has_ext_size) {
        abs = fit_off + align4(fdt.totalsize) + s.ext_off;
        len = s.ext_size;
    } else {
        return std::nullopt;
    }
    if (len == 0 || len > MAX_PAYLOAD) return std::nullopt;
    auto b = r.bytes(static_cast<size_t>(abs), static_cast<size_t>(len));
    if (!b) return std::nullopt;
    return std::vector<uint8_t>(b->begin(), b->end());
}

void emit_sub(const Reader& r, uint64_t fit_off, const Fdt& fdt, const Sub& s, SafeRoot& root,
              const std::string& subdir, Extracted& out) {
    if (s.name.empty()) return;
    auto raw = raw_payload(r, fit_off, fdt, s);
    if (!raw) {
        out.warnings.push_back("section contains no data: " + s.name);
        return;
    }
    std::vector<uint8_t> data;
    if (s.comp == "none") {
        data = std::move(*raw);
    } else {
        Compressor c = comp_of(s.comp);
        if (c == Compressor::Unknown || !compressor_supported(c)) {
            // bzip2 / lzo / unknown: keep the stored bytes, flag it.
            data = std::move(*raw);
            out.warnings.push_back("cannot unpack " + s.comp + " compression: " + s.name);
        } else {
            auto dec = decompress_stream(c, *raw, MAX_PAYLOAD);
            if (dec) {
                data = std::move(*dec);
            } else {
                data = std::move(*raw);
                out.warnings.push_back("could not unpack " + s.comp + " data: " + s.name);
            }
        }
    }
    const std::string rel = subdir + "/" + s.name;
    if (root.write_file(rel, data, 0644)) {
        out.files++;
        out.bytes += data.size();
    } else {
        out.warnings.push_back("write failed: " + s.name);
    }
}

}  // namespace

bool fdt_is_fit(const Reader& r, size_t off, uint64_t* span) {
    auto fo = parse_header(r, off);
    if (!fo) return false;
    const Fdt& fdt = *fo;
    uint64_t pos = fdt.struct_off;
    std::vector<std::string> path;
    bool is_fit = false;
    uint64_t max_end = fdt.totalsize;  // embedded FIT: the span is just the FDT
    // Track external-data extents so the finding can claim appended payloads.
    bool in_sub = false;
    uint64_t cur_size = 0, cur_off = 0, cur_pos = 0;
    bool has_size = false, has_off = false, has_pos = false;

    for (size_t i = 0; i < MAX_TOKENS && pos + 4 <= fdt.struct_end; ++i) {
        auto tok = be32(r, pos);
        if (!tok) break;
        pos += 4;
        if (*tok == FDT_BEGIN_NODE) {
            uint64_t next = 0;
            std::string name = read_cstr(r, pos, fdt.struct_end, next);
            pos = align4(next);
            path.push_back(name);
            if (path.size() == 2 && path[0].empty() && name == "images") is_fit = true;
            if (path.size() == 3 && path[1] == "images") {
                in_sub = true;
                has_size = has_off = has_pos = false;
            } else if (path.size() > 3) {
                in_sub = false;
            }
        } else if (*tok == FDT_END_NODE) {
            if (path.empty()) break;
            const bool closing_sub = (path.size() == 3 && path[1] == "images");
            path.pop_back();
            if (closing_sub && has_size) {
                if (has_pos)
                    max_end = std::max(max_end, cur_pos + cur_size);
                else if (has_off)
                    max_end = std::max(max_end, align4(fdt.totalsize) + cur_off + cur_size);
            }
            in_sub = (path.size() == 3 && path[1] == "images");
        } else if (*tok == FDT_PROP) {
            auto len = be32(r, pos);
            auto nameoff = be32(r, pos + 4);
            if (!len || !nameoff) break;
            const uint64_t vpos = pos + 8;
            pos = vpos + align4(*len);
            if (in_sub) {
                uint64_t d = 0;
                std::string pname = read_cstr(r, fdt.strings_off + *nameoff, fdt.strings_end, d);
                if (pname == "data-size") {
                    if (auto v = be32(r, vpos)) { has_size = true; cur_size = *v; }
                } else if (pname == "data-offset") {
                    if (auto v = be32(r, vpos)) { has_off = true; cur_off = *v; }
                } else if (pname == "data-position") {
                    if (auto v = be32(r, vpos)) { has_pos = true; cur_pos = *v; }
                }
            }
        } else if (*tok == FDT_NOP) {
            // nothing
        } else if (*tok == FDT_END) {
            break;
        } else {
            break;  // malformed token stream
        }
    }
    if (is_fit && span) *span = max_end;
    return is_fit;
}

bool extract_fit(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.offset = f.offset;
    out.type = "fit";
    out.root = subdir;

    auto fo = parse_header(r, f.offset);
    if (!fo) {
        out.status = "error:bad-header";
        return true;
    }
    const Fdt& fdt = *fo;
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    bool truncated = false;
    uint64_t pos = fdt.struct_off;
    std::vector<std::string> path;  // node-name stack; path[0] = root ("")
    Sub cur;
    bool in_sub = false;  // currently inside a /images/<name> node
    size_t subs = 0;

    for (size_t i = 0; i < MAX_TOKENS && pos + 4 <= fdt.struct_end; ++i) {
        auto tok = be32(r, pos);
        if (!tok) { truncated = true; break; }
        pos += 4;
        if (*tok == FDT_BEGIN_NODE) {
            uint64_t next = 0;
            std::string name = read_cstr(r, pos, fdt.struct_end, next);
            pos = align4(next);
            path.push_back(name);
            // A subimage node is a direct child of the root's `images` node:
            // path == ["", "images", "<name>"].
            if (path.size() == 3 && path[1] == "images") {
                if (subs++ >= MAX_SUBIMAGES) { truncated = true; break; }
                cur = Sub{};
                cur.name = name;
                in_sub = true;
            } else if (path.size() > 3) {
                in_sub = false;  // e.g. a hash-1 subnode inside a subimage
            }
        } else if (*tok == FDT_END_NODE) {
            if (path.empty()) { truncated = true; break; }
            const bool closing_sub = (path.size() == 3 && path[1] == "images");
            path.pop_back();
            if (closing_sub) {
                emit_sub(r, f.offset, fdt, cur, root, subdir, out);
                cur = Sub{};
            }
            in_sub = (path.size() == 3 && path[1] == "images");
        } else if (*tok == FDT_PROP) {
            auto len = be32(r, pos);
            auto nameoff = be32(r, pos + 4);
            if (!len || !nameoff) { truncated = true; break; }
            const uint64_t vpos = pos + 8;  // value bytes start here
            pos = vpos + align4(*len);
            if (in_sub) {
                uint64_t dummy = 0;
                std::string pname =
                    read_cstr(r, fdt.strings_off + *nameoff, fdt.strings_end, dummy);
                if (pname == "data") {
                    cur.has_data = true;
                    cur.data_off = vpos;
                    cur.data_len = *len;
                } else if (pname == "data-size") {
                    if (auto v = be32(r, vpos)) { cur.has_ext_size = true; cur.ext_size = *v; }
                } else if (pname == "data-offset") {
                    if (auto v = be32(r, vpos)) { cur.has_ext_off = true; cur.ext_off = *v; }
                } else if (pname == "data-position") {
                    if (auto v = be32(r, vpos)) { cur.has_ext_pos = true; cur.ext_pos = *v; }
                } else if (pname == "compression") {
                    uint64_t d = 0;
                    cur.comp = read_cstr(r, vpos, vpos + *len, d);
                } else if (pname == "type") {
                    uint64_t d = 0;
                    cur.type = read_cstr(r, vpos, vpos + *len, d);
                }
            }
        } else if (*tok == FDT_NOP) {
            // nothing
        } else if (*tok == FDT_END) {
            break;
        } else {
            truncated = true;  // malformed token
            break;
        }
    }

    // If the walk broke mid-subimage (a corrupt tree — some real signed FITs have
    // a bad tag inside the signature node, which even fdtdump fatals on), the
    // current subimage's payload was already parsed before the break. Emit it so
    // we recover the kernel/ramdisk rather than returning nothing.
    if (truncated && (cur.has_data || cur.has_ext_size)) emit_sub(r, f.offset, fdt, cur, root, subdir, out);

    // Record the byte span this FIT occupied (tree + any external data), so a
    // recursive pass and the manifest know what the finding consumed.
    uint64_t span = 0;
    if (fdt_is_fit(r, f.offset, &span)) out.consumed = span;
    out.status = truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

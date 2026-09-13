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
    // Verified-boot metadata (from the subimage's hash-*/signature-* subnodes).
    std::string hash_algo;
    std::string sig_algo;
};

// A collected /configurations/<conf> node.
struct Cfg {
    std::string name, kernel, fdt, sign_images, sig_algo, required;
    bool has_sig = false;
};

// A collected /signature/key-<name> public-key node.
struct Key {
    std::string name, hint, algo, required, num_bits;
    uint64_t n_off = 0, n_len = 0;  // rsa,n (modulus) value bytes (absolute)
    uint64_t e_off = 0, e_len = 0;  // rsa,e (exponent)
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
        out.warnings.push_back("no payload: " + s.name);
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
            out.warnings.push_back("compression " + s.comp + " not decoded: " + s.name);
        } else {
            auto dec = decompress_stream(c, *raw, MAX_PAYLOAD);
            if (dec) {
                data = std::move(*dec);
            } else {
                data = std::move(*raw);
                out.warnings.push_back("decompress failed (" + s.comp + "): " + s.name);
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

bool starts_with(const std::string& s, const char* pre) {
    return s.rfind(pre, 0) == 0;
}

// Write the FIT verified-boot structure as a human-readable sidecar and carve
// the embedded signing keys, so `moria -e` records the signing posture and the
// key material for a downstream fingerprinting/interpretation pass (mithril).
// Structural only: it serializes the tree's signature nodes, it does not judge
// them. Called only when the FIT actually carries signature/key nodes.
void write_fit_metadata(const Reader& r, const std::vector<Sub>& subs, const std::vector<Cfg>& cfgs,
                        const std::vector<Key>& keys, SafeRoot& root, const std::string& subdir,
                        Extracted& out) {
    std::string t = "FIT verified-boot structure\n\n";
    if (!subs.empty()) {
        t += "images:\n";
        for (const auto& s : subs) {
            t += "  " + s.name + "  type=" + (s.type.empty() ? "?" : s.type) + " comp=" + s.comp;
            if (!s.hash_algo.empty()) t += "  hash=" + s.hash_algo;
            if (!s.sig_algo.empty()) t += "  signature=" + s.sig_algo;
            t += "\n";
        }
    }
    if (!cfgs.empty()) {
        t += "configurations:\n";
        for (const auto& c : cfgs) {
            t += "  " + c.name;
            if (!c.kernel.empty()) t += "  kernel=" + c.kernel;
            if (!c.fdt.empty()) t += "  fdt=" + c.fdt;
            if (!c.sign_images.empty()) t += "  sign-images=" + c.sign_images;
            if (c.has_sig) t += "  signature=" + (c.sig_algo.empty() ? "yes" : c.sig_algo);
            if (!c.required.empty()) t += "  required=" + c.required;
            t += "\n";
        }
    }
    if (!keys.empty()) {
        t += "keys:\n";
        for (const auto& k : keys) {
            t += "  " + k.name;
            if (!k.hint.empty()) t += "  hint=" + k.hint;
            if (!k.algo.empty()) t += "  algo=" + k.algo;
            if (!k.num_bits.empty()) t += "  rsa-bits=" + k.num_bits;
            if (!k.required.empty()) t += "  required=" + k.required;
            t += "\n";
        }
    }
    std::vector<uint8_t> tb(t.begin(), t.end());
    if (root.write_file(subdir + "/fit-signature-info.txt", tb, 0644)) {
        out.files++;
        out.bytes += tb.size();
    }
    // Carve each key's public material (modulus + exponent) for fingerprinting.
    for (const auto& k : keys) {
        if (k.n_len == 0) continue;
        std::vector<uint8_t> key;
        if (auto n = r.bytes(static_cast<size_t>(k.n_off), static_cast<size_t>(k.n_len)))
            key.insert(key.end(), n->begin(), n->end());
        if (k.e_len && k.e_len < 64) {
            if (auto e = r.bytes(static_cast<size_t>(k.e_off), static_cast<size_t>(k.e_len)))
                key.insert(key.end(), e->begin(), e->end());
        }
        if (key.empty()) continue;
        std::string safe = k.name.empty() ? "key" : k.name;
        for (char& c : safe)
            if (c == '/' || c == '\\') c = '_';
        if (root.write_file(subdir + "/fit-keys/" + safe + ".bin", key, 0644)) {
            out.files++;
            out.bytes += key.size();
        }
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
    // Verified-boot metadata collected alongside the payloads.
    std::vector<Sub> submetas;
    std::vector<Cfg> cfgs;
    std::vector<Key> keys;
    Cfg cur_cfg;
    Key cur_key;

    for (size_t i = 0; i < MAX_TOKENS && pos + 4 <= fdt.struct_end; ++i) {
        auto tok = be32(r, pos);
        if (!tok) { truncated = true; break; }
        pos += 4;
        if (*tok == FDT_BEGIN_NODE) {
            uint64_t next = 0;
            std::string name = read_cstr(r, pos, fdt.struct_end, next);
            pos = align4(next);
            path.push_back(name);
            const size_t d = path.size();
            // A subimage node is a direct child of the root's `images` node.
            if (d == 3 && path[1] == "images") {
                if (subs++ >= MAX_SUBIMAGES) { truncated = true; break; }
                cur = Sub{};
                cur.name = name;
                in_sub = true;
            } else if (d == 3 && path[1] == "configurations") {
                cur_cfg = Cfg{};
                cur_cfg.name = name;
            } else if (d == 3 && path[1] == "signature" && starts_with(name, "key")) {
                cur_key = Key{};
                cur_key.name = name;
            } else if (d > 3) {
                in_sub = false;  // e.g. a hash-1 subnode inside a subimage
            }
        } else if (*tok == FDT_END_NODE) {
            if (path.empty()) { truncated = true; break; }
            const size_t d = path.size();
            const bool closing_sub = (d == 3 && path[1] == "images");
            const bool closing_cfg = (d == 3 && path[1] == "configurations");
            const bool closing_key = (d == 3 && path[1] == "signature" && starts_with(path[2], "key"));
            path.pop_back();
            if (closing_sub) {
                submetas.push_back(cur);
                emit_sub(r, f.offset, fdt, cur, root, subdir, out);
                cur = Sub{};
            } else if (closing_cfg) {
                cfgs.push_back(cur_cfg);
                cur_cfg = Cfg{};
            } else if (closing_key) {
                keys.push_back(cur_key);
                cur_key = Key{};
            }
            in_sub = (path.size() == 3 && path[1] == "images");
        } else if (*tok == FDT_PROP) {
            auto len = be32(r, pos);
            auto nameoff = be32(r, pos + 4);
            if (!len || !nameoff) { truncated = true; break; }
            const uint64_t vpos = pos + 8;  // value bytes start here
            pos = vpos + align4(*len);
            uint64_t dummy = 0;
            std::string pname = read_cstr(r, fdt.strings_off + *nameoff, fdt.strings_end, dummy);
            auto sval = [&]() { uint64_t d = 0; return read_cstr(r, vpos, vpos + *len, d); };
            const size_t d = path.size();
            if (in_sub) {
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
                    cur.comp = sval();
                } else if (pname == "type") {
                    cur.type = sval();
                }
            } else if (d == 4 && path[1] == "images" && pname == "algo") {
                // a hash-*/signature-* subnode of the subimage (cur still refers to it)
                if (starts_with(path[3], "signature")) cur.sig_algo = sval();
                else if (starts_with(path[3], "hash")) cur.hash_algo = sval();
            } else if (d == 3 && path[1] == "configurations") {
                if (pname == "kernel") cur_cfg.kernel = sval();
                else if (pname == "fdt") cur_cfg.fdt = sval();
                else if (pname == "sign-images") cur_cfg.sign_images = sval();
            } else if (d == 4 && path[1] == "configurations" && starts_with(path[3], "signature")) {
                cur_cfg.has_sig = true;
                if (pname == "algo") cur_cfg.sig_algo = sval();
                else if (pname == "sign-images") cur_cfg.sign_images = sval();
                else if (pname == "required") cur_cfg.required = sval();
            } else if (d == 3 && path[1] == "signature" && starts_with(path[2], "key")) {
                if (pname == "key-name-hint") cur_key.hint = sval();
                else if (pname == "algo") cur_key.algo = sval();
                else if (pname == "required") cur_key.required = sval();
                else if (pname == "rsa,num-bits") {
                    if (auto v = be32(r, vpos)) cur_key.num_bits = std::to_string(*v);
                } else if (pname == "rsa,n") {
                    cur_key.n_off = vpos;
                    cur_key.n_len = *len;
                } else if (pname == "rsa,e") {
                    cur_key.e_off = vpos;
                    cur_key.e_len = *len;
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

    // Record the verified-boot structure + carve the signing keys, when present.
    bool any_sig = !keys.empty();
    for (const auto& s : submetas)
        if (!s.sig_algo.empty()) any_sig = true;
    for (const auto& c : cfgs)
        if (c.has_sig) any_sig = true;
    if (any_sig) write_fit_metadata(r, submetas, cfgs, keys, root, subdir, out);

    // Record the byte span this FIT occupied (tree + any external data), so a
    // recursive pass and the manifest know what the finding consumed.
    uint64_t span = 0;
    if (fdt_is_fit(r, f.offset, &span)) out.consumed = span;
    out.status = truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

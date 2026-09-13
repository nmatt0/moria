// upx.cpp — UPX ELF unpacker. See upx.hpp for the reconstruction outline.
#include "extract/upx.hpp"

#include <algorithm>
#include <cstring>

#include "extract/decompress.hpp"
#include "extract/manifest.hpp"
#include "extract/safepath.hpp"
#include "extract/ucl.hpp"
#include "extract/upx_filter.hpp"

namespace ft {

namespace {

constexpr size_t kMaxOrig = size_t(512) << 20;  // cap on reconstructed size (anti-DoS)
constexpr uint32_t kUpxMagicLe = 0x21585055;    // "UPX!" as a little-endian u32

// One packed image being reconstructed. `pos` is the moving read cursor into the
// packed input; `out` is the output image sized to the original file length.
struct Ctx {
    const Reader& r;
    Endian endian = Endian::Little;  // ELF data encoding (EI_DATA)
    int szb = 12;                    // b_info size: 12 (modern) or 8 (old)
    uint8_t default_method = 0;      // per-file method for old (szb==8) blocks
    size_t pos = 0;
    uint32_t blocksize = 0;
    bool method_unsupported = false;
    bool filter_unsupported = false;
};

// Decode one block to its `sz_unc` uncompressed bytes (decompress + un-filter, or
// pass through a literal block). nullopt on any failure; sets the ctx unsupported
// flags so the caller can report a precise partial status.
std::optional<std::vector<uint8_t>> decode_block(Ctx& c, uint32_t sz_unc, uint32_t sz_cpr,
                                                 uint8_t method, uint8_t ftid, uint8_t cto,
                                                 size_t data_off) {
    auto cspan = c.r.bytes(data_off, sz_cpr);
    if (!cspan) return std::nullopt;
    std::vector<uint8_t> blk;
    if (sz_cpr < sz_unc) {  // compressed
        if (ucl_method_supported(method)) {
            auto d = ucl_nrv_decompress(method, *cspan, sz_unc);
            if (!d) return std::nullopt;
            blk = std::move(*d);
        } else if (method == 14) {  // LZMA: 2-byte UPX property header + raw LZMA1
            if (cspan->size() < 3) return std::nullopt;
            uint8_t b0 = (*cspan)[0], b1 = (*cspan)[1];
            uint8_t pb = b0 & 7, lp = b1 >> 4, lc = b1 & 15;
            if (static_cast<unsigned>(b0 >> 3) != static_cast<unsigned>(lc + lp)) return std::nullopt;
            auto d = upx_lzma_block_exact(cspan->subspan(2), sz_unc, lc, lp, pb);
            if (!d) return std::nullopt;
            blk = std::move(*d);
        } else {
            c.method_unsupported = true;
            return std::nullopt;
        }
        if (ftid) {
            if (!upx_filter_supported(ftid)) {
                c.filter_unsupported = true;
                return std::nullopt;
            }
            upx_unfilter(std::span<uint8_t>(blk.data(), blk.size()), ftid, cto);
        }
    } else if (sz_cpr == sz_unc) {  // stored literal block
        blk.assign(cspan->begin(), cspan->end());
    } else {
        return std::nullopt;
    }
    if (blk.size() != sz_unc) return std::nullopt;
    return blk;
}

// Read a b_info at the cursor. Returns false at end/overrun.
bool read_binfo(Ctx& c, uint32_t& sz_unc, uint32_t& sz_cpr, uint8_t& method, uint8_t& ftid,
                uint8_t& cto, size_t& data_off) {
    auto su = c.r.at<uint32_t>(c.pos, c.endian);
    auto sc = c.r.at<uint32_t>(c.pos + 4, c.endian);
    if (!su || !sc) return false;
    sz_unc = *su;
    sz_cpr = *sc;
    if (c.szb == 12) {
        auto m = c.r.at<uint8_t>(c.pos + 8, c.endian);
        auto ft = c.r.at<uint8_t>(c.pos + 9, c.endian);
        auto ct = c.r.at<uint8_t>(c.pos + 10, c.endian);
        if (!m || !ft || !ct) return false;
        method = *m;
        ftid = *ft;
        cto = *ct;
    } else {  // old style: method is per-file, no per-block filter
        method = c.default_method;
        ftid = 0;
        cto = 0;
    }
    data_off = c.pos + static_cast<size_t>(c.szb);
    return true;
}

// Decompress a contiguous run of blocks totaling `wanted` uncompressed bytes,
// writing them into `out` starting at `dst`. Advances the cursor. Mirrors UPX's
// unpackExtent. Returns false on any failure.
bool unpack_extent(Ctx& c, size_t wanted, std::vector<uint8_t>& out, size_t dst) {
    while (wanted > 0) {
        uint32_t sz_unc, sz_cpr;
        uint8_t method, ftid, cto;
        size_t data_off;
        if (!read_binfo(c, sz_unc, sz_cpr, method, ftid, cto, data_off)) return false;
        if (sz_unc == 0 || sz_cpr == 0 || sz_cpr > sz_unc || sz_unc > c.blocksize) return false;
        if (sz_unc > wanted) return false;
        if (dst > out.size() || sz_unc > out.size() - dst) return false;
        auto blk = decode_block(c, sz_unc, sz_cpr, method, ftid, cto, data_off);
        if (!blk) return false;
        std::memcpy(out.data() + dst, blk->data(), sz_unc);
        dst += sz_unc;
        wanted -= sz_unc;
        c.pos = data_off + sz_cpr;
    }
    return true;
}

// A recovered program header (only the fields the unpacker needs).
struct Phdr {
    uint32_t type = 0;
    uint64_t offset = 0;
    uint64_t filesz = 0;
};

bool is_load(const Phdr& p) { return p.type == 1 /*PT_LOAD*/ && p.filesz > 0; }

// Parse the ELF Ehdr fields (e_phnum) from a decoded header buffer.
bool read_ehdr_phnum(const std::vector<uint8_t>& buf, bool is64, Endian e, uint16_t& phnum) {
    Reader hr(std::span<const uint8_t>(buf.data(), buf.size()));
    auto pn = hr.at<uint16_t>(is64 ? 0x38 : 0x2c, e);
    if (!pn) return false;
    phnum = *pn;
    return true;
}

// Parse program header k from a decoded Ehdr+Phdr buffer.
bool read_phdr(const std::vector<uint8_t>& buf, bool is64, Endian e, size_t k, Phdr& out) {
    Reader hr(std::span<const uint8_t>(buf.data(), buf.size()));
    const size_t ehsize = is64 ? 64 : 52;
    const size_t phsize = is64 ? 56 : 32;
    const size_t base = ehsize + k * phsize;
    if (is64) {
        auto t = hr.at<uint32_t>(base + 0, e);
        auto off = hr.at<uint64_t>(base + 8, e);
        auto fsz = hr.at<uint64_t>(base + 32, e);
        if (!t || !off || !fsz) return false;
        out.type = *t;
        out.offset = *off;
        out.filesz = *fsz;
    } else {
        auto t = hr.at<uint32_t>(base + 0, e);
        auto off = hr.at<uint32_t>(base + 4, e);
        auto fsz = hr.at<uint32_t>(base + 16, e);
        if (!t || !off || !fsz) return false;
        out.type = *t;
        out.offset = *off;
        out.filesz = *fsz;
    }
    return true;
}

// find_LOAD_gap: bytes between the end of PT_LOAD[k] and the next LOAD segment's
// offset (or end-of-file for the last), i.e. the non-loadable region after k.
size_t find_load_gap(const std::vector<Phdr>& ph, size_t k, uint64_t orig_size) {
    if (!is_load(ph[k])) return 0;
    uint64_t hi = ph[k].offset + ph[k].filesz;
    if (hi > orig_size) return 0;
    uint64_t lo = orig_size;
    for (size_t j = 0; j < ph.size(); ++j) {
        if (j == k || !is_load(ph[j])) continue;
        uint64_t t = ph[j].offset;
        if (t >= hi && (t - hi) < (lo - hi)) lo = t;
    }
    return static_cast<size_t>(lo - hi);
}

// The l_info offset for the packed stub at `base`: UPX writes l_info (whose
// l_magic is "UPX!") just past the stub's ELF headers, and it is the first "UPX!"
// in the image (the compressed blocks follow it). Scan a bounded window past the
// Ehdr for that magic; l_info begins 4 bytes before it (l_checksum precedes
// l_magic). Returns the l_info offset, or nullopt.
std::optional<size_t> find_linfo(const Reader& r, size_t base, bool is64) {
    const size_t ehsize = is64 ? 64 : 52;
    const size_t start = base + ehsize;                       // l_info is after the Ehdr
    const size_t limit = std::min(r.size(), base + 0x10000);  // bounded search window
    for (size_t o = start; o + 4 <= limit; ++o) {
        auto m = r.at<uint32_t>(o, Endian::Little);  // l_magic is always LE "UPX!"
        if (m && *m == kUpxMagicLe) return o - 4;    // l_info = magic_off - sizeof(l_checksum)
    }
    return std::nullopt;
}

// Locate the ELF stub base for a UPX trailer at `trailer`: the first ELF header
// followed by an l_info ("UPX!") and a sane p_info. Handles a standalone file
// (base 0) and an ELF embedded in a larger image.
std::optional<size_t> find_base(const Reader& r, size_t trailer) {
    static const uint8_t elf_magic[4] = {0x7f, 'E', 'L', 'F'};
    size_t limit = std::min(trailer, r.size());
    for (size_t o = 0; o + 4 <= limit; ++o) {
        if (!r.matches_at(o, std::span<const uint8_t>(elf_magic, 4))) continue;
        auto cls = r.at<uint8_t>(o + 4, Endian::Little);
        if (!cls || (*cls != 1 && *cls != 2)) continue;
        auto data = r.at<uint8_t>(o + 5, Endian::Little);
        if (!data || (*data != 1 && *data != 2)) continue;
        const bool is64 = (*cls == 2);
        const Endian e = (*data == 2) ? Endian::Big : Endian::Little;
        auto lioff = find_linfo(r, o, is64);
        if (!lioff || *lioff >= trailer) continue;
        // p_info sanity: p_filesize / p_blocksize plausible.
        auto pfs = r.at<uint32_t>(*lioff + 12 + 4, e);
        auto pbs = r.at<uint32_t>(*lioff + 12 + 8, e);
        if (pfs && pbs && *pfs > 0 && *pfs <= kMaxOrig && *pbs > 0 && *pbs <= *pfs) return o;
    }
    return std::nullopt;
}

// Reconstruct with a chosen b_info size. Returns nullopt if the Ehdr block does
// not decode to a valid ELF (so the caller can retry the other szb).
std::optional<UpxUnpack> unpack_with_szb(const Reader& r, size_t lioff, bool is64, Endian e,
                                         int szb, uint8_t elf_class) {
    // l_info: l_lsize @ +8; p_info follows at lioff+12.
    auto pfilesize = r.at<uint32_t>(lioff + 12 + 4, e);
    auto pblocksize = r.at<uint32_t>(lioff + 12 + 8, e);
    if (!pfilesize || !pblocksize) return std::nullopt;
    const uint64_t orig_size = *pfilesize;
    if (orig_size == 0 || orig_size > kMaxOrig || *pblocksize == 0 || *pblocksize > orig_size)
        return std::nullopt;

    Ctx c{r};
    c.endian = e;
    c.szb = szb;
    c.blocksize = *pblocksize;
    c.pos = lioff + 24;  // first b_info, after l_info(12) + p_info(12)

    // First block -> original Ehdr + Phdrs.
    uint32_t su, sc;
    uint8_t method, ftid, cto;
    size_t data_off;
    if (!read_binfo(c, su, sc, method, ftid, cto, data_off)) return std::nullopt;
    if (su == 0 || sc == 0 || sc > su || su > c.blocksize) return std::nullopt;
    c.default_method = method;
    auto ehdr_blk = decode_block(c, su, sc, method, ftid, cto, data_off);
    if (!ehdr_blk || ehdr_blk->size() < (is64 ? 64u : 52u)) return std::nullopt;
    // Must decode to a real ELF header of the same class.
    if ((*ehdr_blk)[0] != 0x7f || (*ehdr_blk)[1] != 'E' || (*ehdr_blk)[2] != 'L' ||
        (*ehdr_blk)[3] != 'F' || (*ehdr_blk)[4] != elf_class)
        return std::nullopt;

    uint16_t u_phnum;
    if (!read_ehdr_phnum(*ehdr_blk, is64, e, u_phnum)) return std::nullopt;
    const size_t phsize = is64 ? 56 : 32;
    const size_t ehsize = is64 ? 64 : 52;
    if (u_phnum == 0 || ehsize + static_cast<size_t>(u_phnum) * phsize > ehdr_blk->size())
        return std::nullopt;
    std::vector<Phdr> phdrs(u_phnum);
    for (size_t k = 0; k < u_phnum; ++k)
        if (!read_phdr(*ehdr_blk, is64, e, k, phdrs[k])) return std::nullopt;

    std::vector<uint8_t> out(static_cast<size_t>(orig_size), 0);

    // Decompress each PT_LOAD to its file offset (the first covers the Ehdr block).
    c.pos = lioff + 24;
    for (const Phdr& p : phdrs) {
        if (!is_load(p)) continue;
        if (p.offset > orig_size || p.filesz > orig_size - p.offset) return std::nullopt;
        if (!unpack_extent(c, static_cast<size_t>(p.filesz), out, static_cast<size_t>(p.offset))) {
            // A method/filter we do not implement: return what we have as partial.
            UpxUnpack res;
            res.data = std::move(out);
            res.status = c.filter_unsupported ? "partial" : c.method_unsupported ? "partial" : "error:decompress";
            res.note = c.filter_unsupported ? "unsupported UPX filter" :
                       c.method_unsupported ? "unsupported UPX method" : "PT_LOAD decompress failed";
            return res;
        }
    }
    const size_t main_end = c.pos;

    // Gaps (inter-segment + trailing non-loadable region) are stored as blocks
    // after the loader. Locate that chain by scanning forward for the b_info run
    // whose uncompressed sizes land exactly on the gap boundaries — robust across
    // UPX loader-layout quirks that the exact loader-skip arithmetic is sensitive
    // to.
    std::vector<std::pair<size_t, size_t>> gaps;  // (phdr index, gap size)
    for (size_t k = 0; k < phdrs.size(); ++k) {
        size_t g = find_load_gap(phdrs, k, orig_size);
        if (g) gaps.push_back({k, g});
    }
    if (!gaps.empty()) {
        auto chain_matches = [&](size_t start) -> bool {
            Ctx probe = c;
            probe.pos = start;
            for (auto& [k, g] : gaps) {
                size_t acc = 0;
                while (acc < g) {
                    uint32_t su2, sc2;
                    uint8_t m2, f2, ct2;
                    size_t doff;
                    if (!read_binfo(probe, su2, sc2, m2, f2, ct2, doff)) return false;
                    if (su2 == 0 || sc2 == 0 || sc2 > su2 || su2 > probe.blocksize) return false;
                    if (!probe.r.bytes(doff, sc2)) return false;
                    acc += su2;
                    probe.pos = doff + sc2;
                    if (acc > g) return false;
                }
            }
            return true;
        };
        size_t gap_start = 0;
        bool found = false;
        for (size_t o = main_end; o + static_cast<size_t>(szb) <= r.size(); ++o) {
            auto su0 = r.at<uint32_t>(o, e);
            if (su0 && *su0 == gaps[0].second && chain_matches(o)) {
                gap_start = o;
                found = true;
                break;
            }
        }
        if (!found) {
            UpxUnpack res;
            res.data = std::move(out);
            res.status = "partial";
            res.note = "gap/tail blocks not located";
            return res;
        }
        c.pos = gap_start;
        for (auto& [k, g] : gaps) {
            size_t where = static_cast<size_t>(phdrs[k].offset + phdrs[k].filesz);
            if (!unpack_extent(c, g, out, where)) {
                UpxUnpack res;
                res.data = std::move(out);
                res.status = c.filter_unsupported || c.method_unsupported ? "partial"
                                                                          : "error:decompress";
                res.note = "gap decompress failed";
                return res;
            }
        }
    }

    UpxUnpack res;
    res.data = std::move(out);
    res.status = "ok";
    return res;
}

}  // namespace

UpxUnpack upx_unpack(const Reader& r, size_t base) {
    auto cls = r.at<uint8_t>(base + 4, Endian::Little);
    auto data = r.at<uint8_t>(base + 5, Endian::Little);
    if (!cls || !data || (*cls != 1 && *cls != 2)) {
        return {std::nullopt, "unsupported:not-elf", "UPX stub is not ELF (PE/Mach-O unsupported)"};
    }
    const bool is64 = (*cls == 2);
    const Endian e = (*data == 2) ? Endian::Big : Endian::Little;
    auto lioff = find_linfo(r, base, is64);
    if (!lioff) return {std::nullopt, "error:no-linfo", "l_info (UPX! magic) not found"};

    // Modern packers use a 12-byte b_info; some ancient x86 packs use 8. Try 12,
    // fall back to 8 if the Ehdr block does not decode to a valid ELF.
    for (int szb : {12, 8}) {
        auto res = unpack_with_szb(r, *lioff, is64, e, szb, *cls);
        if (res) return *res;
    }
    return {std::nullopt, "error:decode", "could not decode packed blocks"};
}

bool extract_upx(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.type = f.type;
    out.root = subdir;

    auto base = find_base(r, static_cast<size_t>(f.offset));
    if (!base) {
        out.offset = f.offset;
        out.status = "error:no-stub";
        return true;
    }
    out.offset = *base;

    UpxUnpack u = upx_unpack(r, *base);
    if (!u.data) {
        out.status = u.status.empty() ? "error:unpack" : u.status;
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    if (!root.write_file(subdir + "/unpacked.elf", *u.data, 0755)) {
        out.status = "error:write";
        return true;
    }
    out.files++;
    out.bytes += u.data->size();
    out.status = u.status.empty() ? "ok" : u.status;
    return true;
}

}  // namespace ft

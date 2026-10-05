// cfbf_parse.cpp — compound file (CFBF) walking. See the header.
#include "cfbf_parse.hpp"

#include <algorithm>
#include <set>

namespace ft {

namespace {

// A compound file is never this large in firmware; the cap keeps a corrupt
// sector count from making us allocate a FAT the file cannot back.
constexpr size_t kMaxSectors = 1u << 24;       // 16M sectors
constexpr size_t kMaxDirEntries = 1u << 18;
constexpr uint64_t kMaxStream = uint64_t(1) << 32;

// MSI encodes its stream names in the 0x3800..0x483F code-unit range, packing
// one or two characters of a 64-symbol alphabet into each UTF-16 unit. Without
// this the tables come out as CJK mojibake and Data1.cab is unrecognizable.
char mime_char(uint32_t id) {
    if (id < 10) return static_cast<char>('0' + id);
    if (id < 36) return static_cast<char>('A' + id - 10);
    if (id < 62) return static_cast<char>('a' + id - 36);
    return id == 62 ? '.' : '_';
}

void append_utf8(std::string& s, uint32_t cp) {
    if (cp < 0x80) {
        s += static_cast<char>(cp);
    } else if (cp < 0x800) {
        s += static_cast<char>(0xC0 | (cp >> 6));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        s += static_cast<char>(0xE0 | (cp >> 12));
        s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

// Decode a directory entry name. Returns the display form and whether any unit
// was MSI-encoded.
//
// U+4840 is not a payload unit: MSI puts it in front of a name to mark the
// stream as one of the database tables. It is dropped, so `_Validation` reads
// as itself rather than carrying a stray CJK character.
std::string decode_name(const std::vector<uint16_t>& units, bool& mangled) {
    mangled = false;
    for (uint16_t u : units)
        if (u >= 0x3800 && u <= 0x4840) mangled = true;

    std::string out;
    for (uint16_t u : units) {
        if (mangled && u == 0x4840) {
            continue;  // MSI table marker, not a character
        } else if (mangled && u >= 0x3800 && u < 0x4800) {
            const uint32_t v = uint32_t(u) - 0x3800;
            out += mime_char(v & 0x3F);
            out += mime_char((v >> 6) & 0x3F);
        } else if (mangled && u >= 0x4800 && u < 0x4840) {
            out += mime_char(uint32_t(u) - 0x4800);
        } else if (u < 0x20) {
            // \x05SummaryInformation and friends: keep the name readable.
            out += '_';
        } else {
            append_utf8(out, u);
        }
    }
    return out;
}

}  // namespace

bool cfbf_parse(const Reader& r, size_t base, Cfbf& out) {
    auto u16 = [&](size_t o) { return r.at<uint16_t>(base + o, Endian::Little); };
    auto u32 = [&](size_t o) { return r.at<uint32_t>(base + o, Endian::Little); };

    auto sig = r.bytes(base, 8);
    static const uint8_t kMagic[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    if (!sig || !std::equal(sig->begin(), sig->end(), kMagic)) return false;

    auto minor = u16(0x18), major = u16(0x1A), order = u16(0x1C);
    auto ssh = u16(0x1E), mssh = u16(0x20);
    auto nfat = u32(0x2C), dir_start = u32(0x30), cutoff = u32(0x38);
    auto mfat_start = u32(0x3C), nmfat = u32(0x40);
    auto difat_start = u32(0x44), ndifat = u32(0x48);
    if (!minor || !major || !order || !ssh || !mssh || !nfat || !dir_start || !cutoff ||
        !mfat_start || !nmfat || !difat_start || !ndifat)
        return false;

    if (*order != 0xFFFE) return false;                    // little-endian only, per spec
    if (*major != 3 && *major != 4) return false;
    if (*ssh < 9 || *ssh > 12 || *mssh != 6) return false;
    out.ver_major = *major;
    out.ver_minor = *minor;
    out.sector_size = 1u << *ssh;
    out.mini_sector_size = 1u << *mssh;
    out.mini_cutoff = *cutoff;

    const size_t ss = out.sector_size;
    const size_t per_sector = ss / 4;
    // Sector n starts one sector in: the header occupies the first sector (512
    // bytes of it, zero-padded to `ss` for the 4 KiB v4 layout).
    auto sector_off = [&](uint32_t n) { return base + size_t(n + 1) * ss; };
    auto sector = [&](uint32_t n) { return r.bytes(sector_off(n), ss); };

    // DIFAT: 109 entries inline, the rest in a chain of DIFAT sectors.
    std::vector<uint32_t> difat;
    difat.reserve(109);
    for (unsigned i = 0; i < 109; ++i) {
        auto v = u32(0x4C + size_t(i) * 4);
        if (!v) return false;
        if (*v <= kCfbfMaxSect) difat.push_back(*v);
    }
    {
        uint32_t s = *difat_start;
        std::set<uint32_t> seen;
        for (uint32_t i = 0; i < *ndifat && s <= kCfbfMaxSect; ++i) {
            if (!seen.insert(s).second) return false;  // DIFAT loop
            auto d = sector(s);
            if (!d) return false;
            for (size_t k = 0; k + 1 < per_sector; ++k) {
                uint32_t v;
                std::memcpy(&v, d->data() + k * 4, 4);
                if (v <= kCfbfMaxSect) difat.push_back(v);
            }
            std::memcpy(&s, d->data() + (per_sector - 1) * 4, 4);
        }
    }
    if (difat.empty() || difat.size() > kMaxSectors / per_sector + 1) return false;

    // FAT: the concatenation of every FAT sector the DIFAT names.
    out.fat.clear();
    out.fat.reserve(std::min<size_t>(difat.size(), *nfat) * per_sector);
    for (size_t i = 0; i < difat.size() && i < *nfat; ++i) {
        auto d = sector(difat[i]);
        if (!d) return false;
        for (size_t k = 0; k < per_sector; ++k) {
            uint32_t v;
            std::memcpy(&v, d->data() + k * 4, 4);
            out.fat.push_back(v);
        }
    }
    if (out.fat.empty()) return false;

    // The file ends after the last sector the FAT accounts for. Trailing FREE
    // entries are padding inside the final FAT sector, not real sectors.
    size_t last = SIZE_MAX;
    for (size_t i = out.fat.size(); i-- > 0;) {
        if (out.fat[i] != kCfbfFree) {
            last = i;
            break;
        }
    }
    if (last == SIZE_MAX) return false;
    out.span = uint64_t(last + 2) * ss;
    const uint64_t avail = r.size() - base;
    if (out.span > avail) out.span = avail;

    // Follow a chain through the regular FAT, collecting sector numbers.
    auto walk = [&](uint32_t start, std::vector<uint32_t>& chain) {
        std::set<uint32_t> seen;
        uint32_t n = start;
        while (n <= kCfbfMaxSect) {
            if (n >= out.fat.size()) return false;
            if (!seen.insert(n).second) return false;  // chain loop
            if (chain.size() > kMaxSectors) return false;
            chain.push_back(n);
            n = out.fat[n];
        }
        return n == kCfbfEndChain;
    };

    // Mini-FAT, for streams below the cutoff.
    out.minifat.clear();
    if (*mfat_start <= kCfbfMaxSect && *nmfat) {
        std::vector<uint32_t> chain;
        if (walk(*mfat_start, chain)) {
            for (uint32_t s : chain) {
                auto d = sector(s);
                if (!d) break;
                for (size_t k = 0; k < per_sector; ++k) {
                    uint32_t v;
                    std::memcpy(&v, d->data() + k * 4, 4);
                    out.minifat.push_back(v);
                }
            }
        }
    }

    // Directory: 128-byte entries across the chain from first_dir_sector.
    std::vector<uint32_t> dir_chain;
    if (!walk(*dir_start, dir_chain)) return false;
    std::vector<uint8_t> dir;
    dir.reserve(dir_chain.size() * ss);
    for (uint32_t s : dir_chain) {
        auto d = sector(s);
        if (!d) return false;
        dir.insert(dir.end(), d->begin(), d->end());
    }

    const size_t count = std::min(dir.size() / 128, kMaxDirEntries);
    out.entries.clear();
    out.entries.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const uint8_t* e = dir.data() + i * 128;
        uint16_t nlen;
        std::memcpy(&nlen, e + 0x40, 2);
        CfbfEntry ce;
        ce.type = e[0x42];
        std::memcpy(&ce.left, e + 0x44, 4);
        std::memcpy(&ce.right, e + 0x48, 4);
        std::memcpy(&ce.child, e + 0x4C, 4);
        std::memcpy(&ce.start, e + 0x74, 4);
        uint32_t lo, hi;
        std::memcpy(&lo, e + 0x78, 4);
        std::memcpy(&hi, e + 0x7C, 4);
        ce.size = uint64_t(lo) | (uint64_t(hi) << 32);
        // v3 files often leave the high dword as garbage; the spec says ignore it.
        if (out.ver_major == 3) ce.size = lo;
        if (ce.type != kCfbfStorage && ce.type != kCfbfStream && ce.type != kCfbfRoot) {
            out.entries.push_back(CfbfEntry{});  // unallocated: keep indices aligned
            continue;
        }
        if (nlen >= 2 && nlen <= 64) {
            std::vector<uint16_t> units;
            for (size_t k = 0; k + 1 < size_t(nlen); k += 2) {
                uint16_t u;
                std::memcpy(&u, e + k, 2);
                if (!u) break;  // the length includes the NUL terminator
                units.push_back(u);
            }
            ce.name = decode_name(units, ce.mangled);
        }
        if (ce.mangled) out.msi = true;
        if (ce.type == kCfbfStream) out.streams++;
        if (ce.type == kCfbfStorage) out.storages++;
        if (ce.type == kCfbfRoot) {
            out.mini_start = ce.start;
            out.mini_size = ce.size;
        }
        out.entries.push_back(std::move(ce));
    }
    if (out.entries.empty()) return false;
    if (out.entries[0].type != kCfbfRoot) return false;
    return true;
}

bool cfbf_stream(const Reader& r, size_t base, const Cfbf& c, const CfbfEntry& e,
                 std::vector<uint8_t>& out) {
    out.clear();
    if (e.size == 0) return true;
    if (e.size > kMaxStream || e.size > r.size()) return false;

    const size_t ss = c.sector_size;
    auto read_chain = [&](const std::vector<uint32_t>& fat, uint32_t start, size_t unit,
                          uint64_t want, auto&& fetch) {
        std::set<uint32_t> seen;
        uint32_t n = start;
        out.reserve(static_cast<size_t>(want));
        while (out.size() < want) {
            if (n > kCfbfMaxSect || n >= fat.size()) return false;
            if (!seen.insert(n).second) return false;  // loop
            auto d = fetch(n);
            if (!d) return false;
            const size_t take = std::min<size_t>(unit, static_cast<size_t>(want) - out.size());
            out.insert(out.end(), d->begin(), d->begin() + static_cast<ptrdiff_t>(take));
            n = fat[n];
        }
        return true;
    };

    if (e.size < c.mini_cutoff && e.type != kCfbfRoot) {
        // Small streams live inside the root entry's mini stream, addressed by
        // the mini-FAT in 64-byte units.
        if (c.minifat.empty()) return false;
        CfbfEntry root;
        root.type = kCfbfRoot;
        root.start = c.mini_start;
        root.size = c.mini_size;
        std::vector<uint8_t> mini;
        if (!cfbf_stream(r, base, c, root, mini)) return false;
        const size_t mu = c.mini_sector_size;
        return read_chain(c.minifat, e.start, mu, e.size, [&](uint32_t n) {
            const size_t off = size_t(n) * mu;
            if (off + mu > mini.size()) return std::optional<std::span<const uint8_t>>{};
            return std::optional<std::span<const uint8_t>>(
                std::span<const uint8_t>(mini).subspan(off, mu));
        });
    }

    return read_chain(c.fat, e.start, ss, e.size,
                      [&](uint32_t n) { return r.bytes(base + size_t(n + 1) * ss, ss); });
}

}  // namespace ft

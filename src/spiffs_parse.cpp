// spiffs_parse.cpp — SPIFFS parser (geometry inference + extract). See the header
// and docs/spiffs-ondisk-notes.md. Clean reimplementation of the SPIFFS on-disk
// layout (MIT) against moria's Reader.
#include "spiffs_parse.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <string>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint16_t IX_FLAG = 0x8000;  // obj_id MSB: object index page (vs data)
constexpr size_t PH = 5;              // page header: obj_id(2) span_ix(2) flags(1)
constexpr size_t ALIGN = 3;           // pad to a 4-byte boundary after the header
constexpr size_t SZ_OFF = PH + ALIGN;      // 8:  u32 size
constexpr size_t TYPE_OFF = SZ_OFF + 4;    // 12: u8 type
constexpr size_t NAME_OFF = TYPE_OFF + 1;  // 13: name[NAME_LEN]
constexpr size_t NAME_LEN = 32;
constexpr uint8_t F_USED = 0x01, F_FINAL = 0x02, F_DELET = 0x80;

uint16_t u16(const Reader& r, size_t o) {
    auto v = r.at<uint16_t>(o, Endian::Little);
    return v ? *v : 0xFFFF;
}
uint32_t u32(const Reader& r, size_t o) {
    auto v = r.at<uint32_t>(o, Endian::Little);
    return v ? *v : 0;
}

// One decoded object: name/size from the FINAL index header, data spans collected.
struct Obj {
    bool have_header = false;
    uint32_t size = 0;
    uint8_t type = 0;
    std::string name;
    std::map<uint16_t, std::pair<size_t, size_t>> spans;  // span_ix -> (data offset, len)
};

// Parse the whole image at a fixed geometry. Fills `objs`; returns false if the
// geometry is structurally impossible. `complete`/`bytes` score the result.
bool parse_at(const Reader& r, uint32_t page, uint32_t block, std::map<uint16_t, Obj>& objs,
              size_t& complete, uint64_t& bytes) {
    const size_t n = r.size();
    if (page < 64 || page > 65536 || (page & (page - 1))) return false;
    if (block < page * 2 || block % page || n % block) return false;
    const uint32_t ppb = block / page;
    const size_t nblocks = n / block;
    const uint32_t lu_pages = (ppb * 2 + page - 1) / page;
    const uint32_t data_bytes = page - PH;

    for (size_t b = 0; b < nblocks; ++b) {
        const size_t base = b * block;
        for (uint32_t p = lu_pages; p < ppb; ++p) {
            const size_t po = base + static_cast<size_t>(p) * page;
            uint16_t oid = u16(r, po);
            if (oid == 0xFFFF) continue;
            uint8_t flags = 0xFF;
            if (auto f = r.at<uint8_t>(po + 4, Endian::Little)) flags = *f;
            if (flags & F_USED) continue;        // not in use
            if (!(flags & F_DELET)) continue;    // deleted
            uint16_t span = u16(r, po + 2);
            uint16_t base_id = oid & ~IX_FLAG;
            if (oid & IX_FLAG) {                 // object index page
                if (span != 0) continue;         // only span 0 carries name/size
                if (flags & F_FINAL) continue;   // stale incremental header
                if (po + NAME_OFF + NAME_LEN > n) return false;
                Obj& o = objs[base_id];
                o.have_header = true;
                o.size = u32(r, po + SZ_OFF);
                if (auto t = r.at<uint8_t>(po + TYPE_OFF, Endian::Little)) o.type = *t;
                auto nm = r.bytes(po + NAME_OFF, NAME_LEN);
                std::string name;
                if (nm)
                    for (uint8_t c : *nm) {
                        if (c == 0) break;
                        name.push_back(static_cast<char>(c));
                    }
                o.name = name;
            } else {                             // data page
                objs[base_id].spans[span] = {po + PH, data_bytes};
            }
        }
    }

    // Keep only real files: a header with a printable name and a sane size.
    complete = 0;
    bytes = 0;
    size_t headers = 0;
    for (auto it = objs.begin(); it != objs.end();) {
        Obj& o = it->second;
        bool ok = o.have_header && !o.name.empty() && o.size <= n;
        for (char c : o.name)
            if (static_cast<uint8_t>(c) < 0x20 || static_cast<uint8_t>(c) >= 0x7f) ok = false;
        if (!ok) { it = objs.erase(it); continue; }
        ++headers;
        // reassembly length
        uint64_t got = 0;
        uint16_t s = 0;
        while (got < o.size) {
            auto sp = o.spans.find(s);
            if (sp == o.spans.end()) break;
            got += sp->second.second;
            ++s;
        }
        if (got >= o.size) ++complete;
        bytes += std::min<uint64_t>(got, o.size);
        ++it;
    }
    return headers > 0;
}

}  // namespace

SpiffsGeom spiffs_infer(const Reader& r) {
    SpiffsGeom best;
    std::array<uint32_t, 5> pages{256, 512, 128, 1024, 2048};
    for (uint32_t page : pages) {
        std::array<uint32_t, 6> blocks{page * 16u, 4096u, 8192u, 65536u, page * 8u, page * 32u};
        for (uint32_t block : blocks) {
            if (block < page * 2 || block % page || r.size() % block) continue;
            std::map<uint16_t, Obj> objs;
            size_t complete = 0;
            uint64_t bytes = 0;
            if (!parse_at(r, page, block, objs, complete, bytes)) continue;
            // Score: most complete files, then most bytes, then most files.
            bool better = !best.ok || complete > best.complete ||
                          (complete == best.complete && bytes > best.total_bytes);
            if (better) {
                best.ok = true;
                best.page_size = page;
                best.block_size = block;
                best.files = objs.size();
                best.complete = complete;
                best.total_bytes = bytes;
            }
        }
    }
    return best;
}

bool spiffs_extract(const Reader& r, const SpiffsGeom& g, SafeRoot& root,
                    const std::string& subdir, SpiffsStats& st) {
    if (!g.ok) return false;
    if (!root.make_dir(subdir)) return false;

    std::map<uint16_t, Obj> objs;
    size_t complete = 0;
    uint64_t bytes = 0;
    if (!parse_at(r, g.page_size, g.block_size, objs, complete, bytes)) return false;

    constexpr size_t kMaxFiles = 200000;
    constexpr uint64_t kMaxBytes = uint64_t(4) << 30;

    for (auto& [id, o] : objs) {
        if (st.files >= kMaxFiles || st.bytes >= kMaxBytes) { st.truncated = true; break; }
        std::vector<uint8_t> content;
        content.reserve(o.size);
        uint16_t s = 0;
        while (content.size() < o.size) {
            auto sp = o.spans.find(s);
            if (sp == o.spans.end()) break;
            size_t take = std::min<size_t>(sp->second.second, o.size - content.size());
            if (auto db = r.bytes(sp->second.first, take))
                content.insert(content.end(), db->begin(), db->end());
            else
                break;
            ++s;
        }
        if (content.size() < o.size) st.truncated = true;  // missing spans
        // The name is an absolute path like "/config.txt"; SafeRoot rejects
        // traversal, and we strip a leading '/'.
        std::string name = o.name;
        while (!name.empty() && name.front() == '/') name.erase(name.begin());
        if (name.empty() || name.find("..") != std::string::npos) continue;
        if (root.write_file(subdir + "/" + name, content, 0644)) {
            st.files++;
            st.bytes += content.size();
        }
    }
    return true;
}

}  // namespace ft

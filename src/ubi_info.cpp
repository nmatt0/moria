#include "ubi_info.hpp"

#include <algorithm>
#include <cstring>
#include <map>

namespace ft {

namespace {
constexpr uint32_t UBI_EC_MAGIC = 0x55424923;   // "UBI#"
constexpr uint32_t UBI_VID_MAGIC = 0x55424921;  // "UBI!"
constexpr uint32_t UBI_LAYOUT_VOL = 0x7fffefff;
constexpr size_t VTBL_REC = 172;      // sizeof(struct ubi_vtbl_record)
constexpr size_t UBI_MAX_VOLS = 128;
constexpr uint64_t MAX_SCAN = uint64_t(2) << 30;  // don't walk past 2 GiB of PEBs

// Sniff a volume's content from the first bytes of its LEB 0.
std::string sniff(const Reader& r, size_t off) {
    auto be = r.at<uint32_t>(off, Endian::Big);
    auto le = r.at<uint32_t>(off, Endian::Little);
    if (le && *le == 0x73717368) return "squashfs";      // "hsqs"
    if (be && *be == 0x27051956) return "uimage";         // U-Boot legacy
    if (be && *be == 0xd00dfeed) return "fit/dtb";        // FDT
    if (le && *le == 0x06101831) return "ubifs";          // UBIFS node
    if (be && *be == 0x1f8b0800) return "gzip";
    return "";
}
}  // namespace

UbiInfo parse_ubi(const Reader& r, size_t base) {
    UbiInfo info;
    auto m0 = r.at<uint32_t>(base, Endian::Big);
    if (!m0 || *m0 != UBI_EC_MAGIC) return info;

    // Detect PEB size from the first two EC headers (scan at 4 KiB granularity).
    uint64_t first = 0, second = 0;
    bool f1 = false;
    for (uint64_t p = base; p + 4 <= r.size() && p < base + (uint64_t(16) << 20); p += 4096) {
        auto m = r.at<uint32_t>(p, Endian::Big);
        if (!m || *m != UBI_EC_MAGIC) continue;
        if (!f1) { first = p; f1 = true; }
        else { second = p; break; }
    }
    if (!f1) return info;
    const uint64_t peb = (second > first) ? second - first : (r.size() - first);
    if (peb < 512 || peb > (uint64_t(64) << 20)) return info;
    info.peb = peb;

    // Walk PEBs: record the newest (highest sqnum) LEB0 data offset per vol_id,
    // the usable LEB length, the UBI extent, and the layout-volume LEB0.
    struct Slot { uint64_t sqnum; size_t data_off; };
    std::map<uint32_t, Slot> leb0;   // vol_id -> best LEB0
    uint64_t leb_len = 0;
    size_t last_peb_end = base;
    size_t layout_off = 0;
    uint64_t layout_sq = 0;
    for (uint64_t p = base; p + 64 <= r.size() && p < base + MAX_SCAN; p += peb) {
        auto ec = r.at<uint32_t>(p, Endian::Big);
        if (!ec || *ec != UBI_EC_MAGIC) break;  // end of the contiguous UBI
        last_peb_end = static_cast<size_t>(p + peb);
        info.peb_vol.push_back(0xFFFFFFFF);  // default free; set below when mapped
        auto vid_off = r.at<uint32_t>(p + 0x10, Endian::Big);
        auto data_off = r.at<uint32_t>(p + 0x14, Endian::Big);
        if (!vid_off || !data_off || *data_off >= peb) continue;
        const uint64_t v = p + *vid_off;
        auto vm = r.at<uint32_t>(v, Endian::Big);
        if (!vm || *vm != UBI_VID_MAGIC) continue;  // free PEB
        auto vol_id = r.at<uint32_t>(v + 8, Endian::Big);
        auto lnum = r.at<uint32_t>(v + 12, Endian::Big);
        auto sq = r.at<uint64_t>(v + 40, Endian::Big);
        if (!vol_id || !lnum || !sq) continue;
        info.peb_vol.back() = *vol_id;
        leb_len = peb - *data_off;
        if (*vol_id == UBI_LAYOUT_VOL) {
            if (*lnum == 0 && *sq >= layout_sq) { layout_sq = *sq; layout_off = static_cast<size_t>(p + *data_off); }
            continue;
        }
        if (*lnum != 0) continue;  // only need LEB0 per volume for id/sniff
        auto& s = leb0[*vol_id];
        if (s.data_off == 0 || *sq > s.sqnum) s = {*sq, static_cast<size_t>(p + *data_off)};
    }
    if (!layout_off || !leb_len) return info;

    info.start = base;
    info.end = last_peb_end;

    // Parse the volume table (array of ubi_vtbl_record) from the layout LEB0.
    auto vtbl = r.bytes(layout_off, std::min<uint64_t>(leb_len, VTBL_REC * UBI_MAX_VOLS));
    if (!vtbl) return info;
    const uint8_t* t = vtbl->data();
    size_t navail = vtbl->size();
    for (uint32_t id = 0; id < UBI_MAX_VOLS; ++id) {
        size_t rec = id * VTBL_REC;
        if (rec + VTBL_REC > navail) break;
        uint32_t reserved_pebs =
            (uint32_t(t[rec]) << 24) | (t[rec + 1] << 16) | (t[rec + 2] << 8) | t[rec + 3];
        uint8_t vol_type = t[rec + 12];
        uint16_t name_len = (uint16_t(t[rec + 14]) << 8) | t[rec + 15];
        if (reserved_pebs == 0 || name_len == 0 || name_len > 127) continue;
        UbiVolume vol;
        vol.vol_id = id;
        vol.name.assign(reinterpret_cast<const char*>(t + rec + 16), name_len);
        // keep it printable
        for (char& c : vol.name)
            if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) >= 0x7f) c = '.';
        vol.is_static = (vol_type == 2);
        vol.size = uint64_t(reserved_pebs) * leb_len;
        auto it = leb0.find(id);
        if (it != leb0.end()) vol.content = sniff(r, it->second.data_off);
        info.volumes.push_back(std::move(vol));
    }
    info.ok = !info.volumes.empty();
    return info;
}

std::vector<Finding> enrich_ubi_findings(const Reader& r, std::vector<Finding> fs, bool all) {
    if (all) return fs;

    // Discover UBI extents from the ubi findings (skip ones already covered).
    std::vector<UbiInfo> ubis;
    for (const auto& f : fs) {
        if (f.type != "ubi") continue;
        bool covered = false;
        for (const auto& u : ubis)
            if (f.offset >= u.start && f.offset < u.end) { covered = true; break; }
        if (covered) continue;
        UbiInfo u = parse_ubi(r, f.offset);
        if (u.ok) ubis.push_back(std::move(u));
    }
    if (ubis.empty()) return fs;

    auto extent_of = [&](size_t off) -> int {
        for (size_t i = 0; i < ubis.size(); ++i)
            if (off >= ubis[i].start && off < ubis[i].end) return static_cast<int>(i);
        return -1;
    };

    // Build one enriched ubi finding per extent, with its volumes as members.
    std::vector<Finding> ubifind(ubis.size());
    std::vector<std::map<uint32_t, size_t>> vol_member(ubis.size());  // vol_id -> member index
    for (size_t i = 0; i < ubis.size(); ++i) {
        const UbiInfo& u = ubis[i];
        Finding& f = ubifind[i];
        f.offset = u.start;
        f.size = u.end - u.start;
        f.type = "ubi";
        f.category = "filesystem";
        f.endian = Endian::Big;
        size_t nv = u.volumes.size();
        f.set_confidence(Confidence::Verified,
                         "UBI volume table: " + std::to_string(nv) + " volume" +
                             (nv != 1 ? "s" : ""));
        f.description = "UBI (Unsorted Block Images) volume on raw NAND flash.";
        for (const auto& v : u.volumes) {
            std::string note = v.content.empty() ? (v.is_static ? "static" : "dynamic")
                                                 : v.content;
            vol_member[i][v.vol_id] = f.members.size();
            f.members.push_back({v.name, static_cast<size_t>(v.size), note, {}});
        }
    }

    // Keep everything outside a UBI. Embedded crypto hits (keys/certs) inside a
    // UBI attach to the volume whose PEBs hold them (so they nest under that
    // volume); ones in free/unmapped PEBs stay as direct children of the ubi. The
    // rest of the interior (per-PEB ubi/ubifs, the volumes, image/compression
    // noise) is dropped — it is represented by the volume members.
    std::vector<Finding> out;
    for (auto& f : fs) {
        int e = extent_of(f.offset);
        if (e < 0) { out.push_back(std::move(f)); continue; }
        if (f.category != "crypto") continue;
        uint32_t vid = ubis[e].volume_at(f.offset);
        auto it = vol_member[e].find(vid);
        if (it != vol_member[e].end())
            ubifind[e].members[it->second].children.push_back(std::move(f));
        else
            out.push_back(std::move(f));  // free PEB: nest directly under the ubi
    }

    for (auto& f : ubifind) out.push_back(std::move(f));
    std::sort(out.begin(), out.end(),
              [](const Finding& a, const Finding& b) { return a.offset < b.offset; });
    return out;
}

}  // namespace ft

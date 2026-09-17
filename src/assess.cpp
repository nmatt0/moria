#include "assess.hpp"

#include <algorithm>

#include "entropy.hpp"
#include "resolve.hpp"

namespace ft {

namespace {
constexpr double HIGH_ENTROPY = 7.2;  // >= this over a sizable region ⇒ likely encrypted/compressed
}  // namespace

// Entropy over [off,off+len), sampling if the region is large.
double region_entropy(const Reader& r, size_t off, size_t len) {
    constexpr size_t CAP = 1u << 20;  // sample at most 1 MiB
    if (len <= CAP) {
        if (auto b = r.bytes(off, len)) return shannon_entropy(*b);
        return 0.0;
    }
    // Strided sample: 16 chunks of 64 KiB across the region.
    std::vector<uint8_t> buf;
    const size_t chunk = 64 * 1024, chunks = 16;
    const size_t stride = len / chunks;
    for (size_t i = 0; i < chunks; ++i) {
        size_t at = off + i * stride;
        size_t take = std::min(chunk, len - (at - off));
        if (auto b = r.bytes(at, take)) buf.insert(buf.end(), b->begin(), b->end());
    }
    return shannon_entropy(buf);
}

double whole_file_entropy(const Reader& r) { return region_entropy(r, 0, r.size()); }

std::vector<Region> unidentified_regions(const Reader& r, const std::vector<Finding>& findings,
                                         size_t min_size) {
    // Coverage from the structural findings, PLUS the merged filesystem/container
    // regions. The latter matters for per-node flash filesystems (UBI/UBIFS):
    // their interior compressed data nodes are not separately claimed, so without
    // the merged region a filesystem's insides would be reported as hundreds of
    // "unidentified high-entropy" gaps (they are just compressed fs data, not
    // encryption).
    std::vector<std::pair<size_t, size_t>> spans;
    for (const auto& f : findings)
        if (f.size > 0) spans.push_back({f.offset, f.offset + f.size});
    for (const auto& r : container_regions(findings)) spans.push_back(r);
    std::sort(spans.begin(), spans.end());

    std::vector<Region> out;
    size_t cursor = 0;
    const size_t end = r.size();
    auto add_gap = [&](size_t a, size_t b) {
        if (b > a && (b - a) >= min_size)
            out.push_back({a, b - a, region_entropy(r, a, b - a)});
    };
    for (const auto& [s, e] : spans) {
        if (s > cursor) add_gap(cursor, s);
        cursor = std::max(cursor, e);
    }
    add_gap(cursor, end);
    return out;
}

std::string assess_file(const std::vector<Finding>& findings, size_t file_size,
                        const std::vector<Region>& regions, double file_entropy, bool entropy_on) {
    // Distinct types in offset order. Crypto hits (keys/certs) embedded in a
    // container's members (a UBI volume's keys/certs) are counted too.
    std::vector<std::string> types;
    int crypto = 0;
    for (const auto& f : findings) {
        if (f.category == "crypto") ++crypto;
        for (const auto& m : f.members)
            for (const auto& c : m.children)
                if (c.category == "crypto") ++crypto;
        if (std::find(types.begin(), types.end(), f.type) == types.end()) types.push_back(f.type);
    }

    size_t covered = 0;
    for (const auto& f : findings) covered += f.size;

    bool big_high_entropy = false;
    if (entropy_on)
        for (const auto& reg : regions)
            if (reg.size >= 4096 && reg.entropy >= HIGH_ENTROPY) { big_high_entropy = true; break; }

    std::string s;
    if (types.empty()) {
        s = "no known structures identified";
        if (entropy_on) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.1f", file_entropy);
            s = "no known structures; whole-file entropy " + std::string(buf);
            if (file_entropy >= HIGH_ENTROPY) s += " - likely encrypted or compressed";
        }
    } else {
        for (size_t i = 0; i < types.size(); ++i) {
            if (i) s += " + ";
            s += types[i];
        }
        // Note a large unclaimed high-entropy tail/gap even when we found structures.
        if (big_high_entropy && covered < file_size)
            s += "; high-entropy unidentified region(s) - possible encryption";
    }
    if (crypto) s += "; " + std::to_string(crypto) + " key/cert";
    return s;
}

std::string assess_tree(const TreeResult& tr) {
    const size_t crypto = tr.crypto_count;
    std::string s = std::to_string(tr.file_count) + " files";
    // top few types by count
    int shown = 0;
    for (const auto& [type, count] : tr.by_type) {
        if (type == "unknown" || type == "unreadable") continue;
        s += (shown == 0 ? ": " : ", ");
        s += std::to_string(count) + " " + type;
        if (++shown >= 5) break;
    }
    if (crypto) s += "; " + std::to_string(crypto) + " key/cert";
    return s;
}

}  // namespace ft

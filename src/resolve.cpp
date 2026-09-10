#include "resolve.hpp"

#include <algorithm>

namespace ft {

namespace {

// Deterministic total order: earliest offset first, then strongest, then
// largest, then type name, then endianness. Fully deterministic (no random tiebreak).
bool less(const Finding& a, const Finding& b) {
    if (a.offset != b.offset) return a.offset < b.offset;
    if (a.confidence != b.confidence) return a.confidence > b.confidence;
    if (a.size != b.size) return a.size > b.size;
    if (a.type != b.type) return a.type < b.type;
    return static_cast<int>(a.endian) < static_cast<int>(b.endian);
}

Finding demote(Finding f) {
    f.also_matched.clear();  // don't nest also_matched inside also_matched
    return f;
}

}  // namespace

std::vector<Finding> resolve(std::vector<Finding> candidates, size_t file_size,
                             const std::set<std::string>& coalesce_types) {
    std::sort(candidates.begin(), candidates.end(), less);

    std::vector<Finding> kept;
    size_t owner_end = 0;  // end of the span owned by the current owner
    int owner = -1;        // index in `kept` of the owning region, or -1

    for (auto& f : candidates) {
        // Same offset as the last kept finding -> a weaker competitor.
        if (!kept.empty() && f.offset == kept.back().offset) {
            kept.back().also_matched.push_back(demote(f));
            continue;
        }
        // Starts inside a region already owned by a confident, sized finding.
        if (f.offset < owner_end) {
            if (owner >= 0) kept[owner].also_matched.push_back(demote(f));
            continue;
        }
        // Keep it.
        kept.push_back(std::move(f));
        const Finding& k = kept.back();
        if (k.confidence >= static_cast<uint8_t>(Confidence::Structural) && k.size > 0) {
            owner_end = k.offset + k.size;
            owner = static_cast<int>(kept.size()) - 1;
        }
    }

    // Size inference: a finding with unknown size runs to the next kept
    // finding, or to EOF. (Overestimates on a false negative; that is the
    // safer error for a map. See phase2-design §7.)
    for (size_t i = 0; i < kept.size(); ++i) {
        if (kept[i].size == 0) {
            size_t next_off = (i + 1 < kept.size()) ? kept[i + 1].offset : file_size;
            if (next_off >= kept[i].offset) kept[i].size = next_off - kept[i].offset;
        }
    }

    if (coalesce_types.empty()) return kept;

    // Coalesce runs of coalesce-flagged findings (jffs2 nodes, ubi erase-blocks,
    // interleaved ubi/ubifs) into one region. The run BRIDGES intervening
    // non-coalesce findings (an embedded cert, a small volume header) up to
    // COALESCE_GAP, so a per-PEB flash filesystem does not fragment into
    // hundreds of rows every time a node sits between two erase blocks. Non-
    // coalesce findings are kept in place; a large one (a whole squashfs volume)
    // exceeds the gap and naturally starts a fresh region after it.
    constexpr size_t COALESCE_GAP = 512 * 1024;
    std::vector<Finding> merged;
    int open = -1;  // index in `merged` of the current open coalesce region
    for (auto& f : kept) {
        if (coalesce_types.count(f.type)) {
            if (open >= 0 &&
                f.offset <= merged[open].offset + merged[open].size + COALESCE_GAP) {
                Finding& m = merged[open];
                size_t end = std::max(m.offset + m.size, f.offset + f.size);
                m.size = end - m.offset;
                m.coalesced_count += 1;
                m.evidence = std::to_string(m.coalesced_count) + " flash areas combined";
                continue;
            }
            f.coalesced_count = 1;
            merged.push_back(std::move(f));
            open = static_cast<int>(merged.size()) - 1;
        } else {
            merged.push_back(std::move(f));  // kept in place; does not close the region
        }
    }
    return merged;
}

std::vector<std::pair<size_t, size_t>> container_regions(const std::vector<Finding>& findings,
                                                         size_t gap) {
    // The gap bridges a per-PEB flash grid (UBI PEBs are typically 128-256 KB
    // apart, with the erase-block's own compressed data in between), so a run of
    // small per-PEB findings interleaved with those nodes becomes one region.
    std::vector<std::pair<size_t, size_t>> regions;
    for (const auto& f : findings) {
        if ((f.category == "filesystem" || f.category == "container") && f.size > 0) {
            size_t s = f.offset, e = f.offset + f.size;
            if (!regions.empty() && s <= regions.back().second + gap)
                regions.back().second = std::max(regions.back().second, e);
            else
                regions.push_back({s, e});
        }
    }
    return regions;
}

std::vector<Finding> suppress_interior_findings(std::vector<Finding> findings, bool all,
                                                size_t* dropped) {
    if (dropped) *dropped = 0;
    if (all) return findings;

    // A finding is interior noise if some OTHER filesystem/container finding
    // strictly encloses it: the container's own extractor owns everything inside
    // it (a squashfs/UBIFS's compressed nodes, an android_boot's kernel/ramdisk,
    // and the spurious magic hits that land inside compressed data), so those must
    // not leak out as peer top-level findings or drive redundant/failed
    // extractions. Strict containment (the enclosed extent is a proper subrange)
    // never drops the enclosing container itself. `-A/--all` keeps everything.
    const size_t n = findings.size();
    std::vector<char> drop(n, 0);
    for (size_t i = 0; i < n; ++i) {
        const Finding& g = findings[i];
        // A whole-archive tar (its validator computes the full span) also owns its
        // interior: each member header carries the "ustar" magic, so without this
        // those matches would survive as peers and each re-extract the tail.
        if (!((g.category == "filesystem" || g.category == "container" || g.category == "archive") &&
              g.size > 0))
            continue;
        const size_t gs = g.offset, ge = g.offset + g.size;
        for (size_t j = 0; j < n; ++j) {
            if (j == i || drop[j]) continue;
            const Finding& f = findings[j];
            const size_t fs = f.offset, fe = f.offset + std::max<size_t>(f.size, 1);
            // f is a proper subrange of g (contained, and smaller on at least one side).
            if (fs >= gs && fe <= ge && (fs > gs || fe < ge)) drop[j] = 1;
        }
    }

    std::vector<Finding> out;
    out.reserve(n);
    for (size_t j = 0; j < n; ++j) {
        if (drop[j]) {
            if (dropped) (*dropped)++;
            continue;
        }
        out.push_back(std::move(findings[j]));
    }
    return out;
}

}  // namespace ft

#include "scan.hpp"

#include <cstdint>
#include <optional>
#include <set>
#include <string>

#include "ahocorasick.hpp"
#include "resolve.hpp"

namespace ft {

namespace {

Finding make_finding(const Signature& sig) {
    Finding f;
    f.type = sig.name;
    f.category = sig.category;
    f.description = sig.description;
    f.vendor = sig.vendor;
    f.references = sig.references;
    f.limitations = sig.limitations;
    return f;
}

const char* tier_evidence(Confidence c) {
    switch (c) {
        case Confidence::Magic: return "magic match";
        case Confidence::Structural: return "header fields satisfy constraints";
        case Confidence::Consistent: return "cross-field checks consistent";
        case Confidence::Verified: return "content verified";
        case Confidence::Reject: return "";
    }
    return "";
}

// Validate one signature at `off` with a specific endianness (the magic that
// matched already selected it). Returns the Finding or nullopt (false positive).
std::optional<Finding> validate_one(const Reader& r, const Signature& sig, size_t off,
                                    Endian endian) {
    const uint64_t avail = r.size() - off;

    FieldMap fields;
    if (!sig.layout.empty()) {
        auto fm = sig.layout.extract(r, off, endian);
        if (!fm) return std::nullopt;  // header runs past EOF
        fields = std::move(*fm);
    }

    auto resolve_var = [&](const std::string& n) -> uint64_t {
        if (n == "_avail") return avail;
        if (n == "_offset") return off;
        auto it = fields.find(n);
        return it == fields.end() ? 0 : it->second;
    };

    for (const auto& c : sig.constraints)
        if (eval_expr(*c, resolve_var) == 0) return std::nullopt;

    Finding cand = make_finding(sig);
    cand.offset = off;
    cand.endian = endian;

    // Soft (validity) constraints: the hard constraints already established this
    // is the format; if a soft one fails, a field is out of range — surface it
    // as a `magic`-tier finding (size unknown, no size-from-a-bogus-field, no
    // validator) rather than dropping it. A corrupt-but-real superblock then
    // shows up as "present, field out of range" instead of nothing.
    for (const auto& c : sig.soft_constraints) {
        if (eval_expr(*c, resolve_var) == 0) {
            cand.size = 0;
            cand.set_confidence(Confidence::Magic, sig.soft_evidence);
            return cand;
        }
    }

    if (sig.size_expr) {
        uint64_t sz = eval_expr(*sig.size_expr, resolve_var);
        if (sz > avail) {
            if (!sig.size_clamp) return std::nullopt;  // size past EOF = false positive
            sz = avail;                                // unless the format allows it (ext on a dump)
        }
        cand.size = sz;
    }

    cand.set_confidence(sig.pass_tier, tier_evidence(sig.pass_tier));

    if (sig.validator) {
        ValidatorCtx ctx{r, off, endian, fields, cand};
        if (!sig.validator(ctx)) return std::nullopt;
    }
    return cand;
}

// Maps an Aho-Corasick pattern id back to its signature and match parameters.
struct PatternRef {
    uint32_t sig_index;
    Endian endian;
    bool short_sig;
    size_t magic_offset;
};

}  // namespace

std::vector<Finding> scan(const Reader& r, const std::vector<Signature>& sigs) {
    const size_t n = r.size();
    if (n < 4) return {};

    // Build the automaton from every magic of every signature.
    AhoCorasick ac;
    std::vector<PatternRef> refs;
    for (uint32_t si = 0; si < sigs.size(); ++si) {
        for (const auto& m : sigs[si].magics) {
            uint32_t id = static_cast<uint32_t>(refs.size());
            refs.push_back({si, m.endian, sigs[si].short_sig, sigs[si].magic_offset});
            ac.add(m.bytes, id);
        }
    }
    ac.build();

    std::set<std::string> coalesce_types;
    for (const auto& s : sigs)
        if (s.coalesce) coalesce_types.insert(s.name);

    // Scan with skip-ahead: once a confident, sized finding claims a region,
    // restart the automaton past it so we neither validate nor traverse its
    // interior (the compressed blocks inside a squashfs, etc.).
    // That size is self-declared, though, and can overrun a region the partition
    // table already accounts for (a stale superblock in unpartitioned space
    // still recording its pre-repartition size). Skipping the whole extent would
    // step over those partitions' superblocks without ever validating them, so
    // they would be missed entirely rather than demoted. Clamp the jump at the
    // next partition start.
    std::set<size_t> part_starts;  // absolute partition offsets seen so far
    std::vector<Finding> candidates;
    size_t next_scan = 0;
    while (next_scan < n) {
        size_t skip_to = 0;
        ac.find(r.data(), next_scan, [&](size_t off, uint32_t id) -> bool {
            const PatternRef& pr = refs[id];
            if (pr.short_sig && off != pr.magic_offset) return true;  // short magics only at start
            if (off < pr.magic_offset) return true;                   // structure would start before 0
            size_t base = off - pr.magic_offset;
            auto f = validate_one(r, sigs[pr.sig_index], base, pr.endian);
            if (!f) return true;
            const bool owns_region =
                f->confidence >= static_cast<uint8_t>(Confidence::Structural) && f->size > 0;
            const size_t foff = f->offset;
            const size_t end = foff + f->size;
            for (const auto& m : f->members)
                if (m.offset != SIZE_MAX) part_starts.insert(m.offset);
            candidates.push_back(std::move(*f));
            if (owns_region) {
                size_t lim = end;
                auto it = part_starts.upper_bound(foff);  // first boundary after it
                if (it != part_starts.end() && *it < lim) lim = *it;
                skip_to = lim;  // > foff >= next_scan, so the loop still advances
                return false;
            }
            return true;
        });
        if (skip_to > next_scan)
            next_scan = skip_to;
        else
            break;  // scanned to EOF with nothing left to skip
    }

    return resolve(std::move(candidates), n, coalesce_types);
}

}  // namespace ft

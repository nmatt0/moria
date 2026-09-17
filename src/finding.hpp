// finding.hpp — the identification result types + confidence rubric.
// Mirrors the output JSON schema.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "reader.hpp"

namespace ft {

// Confidence rubric (phase2-design §4): numeric 0-100 with named tiers.
// The enum value IS the numeric score, so we carry both cheaply.
enum class Confidence : uint8_t {
    Reject = 0,
    Magic = 25,        // magic matched; structure not (yet) validated
    Structural = 60,   // header parsed, all non-reject constraints pass
    Consistent = 85,   // cross-field / internal-pointer consistency verified
    Verified = 99,     // CRC/checksum or decode probe succeeded
};

inline const char* tier_name(Confidence c) {
    switch (c) {
        case Confidence::Magic: return "magic";
        case Confidence::Structural: return "structural";
        case Confidence::Consistent: return "consistent";
        case Confidence::Verified: return "verified";
        case Confidence::Reject: return "reject";
    }
    return "reject";
}

struct Reference {
    std::string title;
    std::string url;
};

// A diagnostic: something the reader should know about a finding (or the file)
// that the identification itself does not convey — a degraded result or a
// caveat. `severity` is "error" (moria could not do something it normally does),
// "warning" (a caveat or reduced confidence), or "info" (a neutral note).
// `code` is a stable machine slug (e.g. "yaffs2-no-oob"); `message` is the human
// sentence. When attached to a finding, its offset/type come from the finding.
struct Diagnostic {
    std::string severity;
    std::string code;
    std::string message;
};

// An archive member (name + uncompressed size), from --list; also a container's
// sub-component (a UBI volume). `note` carries a short descriptor (a UBI
// volume's content type, e.g. "squashfs" / "ubifs · dynamic"); empty otherwise.
struct Finding;

struct Member {
    std::string name;
    size_t size;
    std::string note;
    std::vector<Finding> children;  // findings that live inside this member (a UBI volume)
    // Absolute byte offset in the image, when the member is a located region (a
    // GPT/MBR partition). SIZE_MAX = no offset (an archive member / UBI volume,
    // which has no single image offset); such members render name-only.
    size_t offset = SIZE_MAX;
    // Shannon entropy (bits/byte, 0-8) over this member's byte range; computed
    // only under -E for located members. <0 = not computed.
    double entropy = -1.0;
};

struct Finding {
    size_t offset = 0;
    size_t size = 0;  // 0 = unknown/unspecified
    std::string type;
    std::string category;

    uint8_t confidence = 0;            // 0-100
    std::string confidence_tier;       // "structural", ...
    std::string evidence;              // short human reason for the score

    Endian endian = Endian::Little;

    // Optional descriptive fields; emitted only when non-empty.
    std::string version;
    std::string label;  // format-specific name embedded in the data (e.g. uImage image name)
    std::string compression;
    std::string arch;

    // Shannon entropy (bits/byte, 0-8) over this finding's byte range; computed
    // only under -E. <0 = not computed (the default, so it is never emitted).
    double entropy = -1.0;

    // Doc metadata (from the signature definition).
    std::string description;
    std::string vendor;
    std::vector<Reference> references;
    std::vector<std::string> limitations;

    // Diagnostics about this finding (missing OOB, CRC mismatch, clamped size,
    // partial extraction, ...). Surfaced in the NOTES column and the diagnostics
    // section/array; empty for a clean finding.
    std::vector<Diagnostic> diagnostics;

    // Number of same-type regions merged into this one (per-node formats). 1 = not coalesced.
    uint32_t coalesced_count = 1;

    // Archive members (from --list); empty unless this is a listed archive.
    std::vector<Member> members;
    bool members_truncated = false;

    // Populated by conflict resolution (M2): signatures suppressed at this offset.
    std::vector<Finding> also_matched;

    void set_confidence(Confidence c, std::string why) {
        confidence = static_cast<uint8_t>(c);
        confidence_tier = tier_name(c);
        evidence = std::move(why);
    }
};

}  // namespace ft

// signature.hpp — a format signature: magic patterns + declarative layout +
// constraints + optional size expr + optional named C++ validator + doc.
// Loaded from TOML (see sigload.hpp / signatures/*.toml).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "expr.hpp"
#include "finding.hpp"
#include "layout.hpp"
#include "reader.hpp"

namespace ft {

struct MagicPattern {
    std::vector<uint8_t> bytes;
    Endian endian;
};

// Handed to a validator: the reader, the match offset+endian, the already-parsed
// header fields, and the Finding to refine. A validator may raise/lower the
// confidence tier, set size/version/compression/arch, or reject (return false).
struct ValidatorCtx {
    const Reader& reader;
    size_t offset;
    Endian endian;
    const FieldMap& fields;
    Finding& out;
};
using Validator = bool (*)(ValidatorCtx&);

struct Signature {
    std::string name;
    std::string category;
    bool short_sig = false;
    size_t magic_offset = 0;          // offset of the magic bytes from the structure start
    std::vector<MagicPattern> magics;

    Layout layout;                    // may be empty
    std::vector<ExprPtr> constraints; // all must pass, else the hit is rejected
    // Validity checks that are NOT identity: if the hard `constraints` all pass
    // but a soft one fails, the structure is recognizably this format but a
    // field is out of range — emit a `magic`-tier finding (size unknown) rather
    // than rejecting. Lets a corrupt-but-real superblock surface as "present,
    // field out of range" instead of vanishing. Empty for almost every sig.
    std::vector<ExprPtr> soft_constraints;
    std::string soft_evidence;        // evidence string for the downgraded finding
    ExprPtr size_expr;                // nullable; result compared against bytes-to-EOF
    bool size_clamp = false;          // if size_expr exceeds EOF, clamp instead of rejecting
    bool coalesce = false;            // merge consecutive same-type findings (per-node formats)
    Confidence pass_tier = Confidence::Magic;  // tier assigned when constraints pass

    std::string validator_name;       // "" = none
    Validator validator = nullptr;    // resolved from validator_name at load

    // Doc metadata copied into each Finding.
    std::string description;
    std::string vendor;
    std::vector<Reference> references;
    std::vector<std::string> limitations;
};

}  // namespace ft

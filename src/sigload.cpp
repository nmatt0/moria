#include "sigload.hpp"

#include <algorithm>
#include <filesystem>
#include <set>
#include <stdexcept>
#include <unordered_set>
#include <utility>

#include "tomlplusplus/toml.hpp"
#include "validators/registry.hpp"

namespace ft {

namespace {

namespace fs = std::filesystem;

Endian parse_endian(const std::string& s) {
    return (s == "big" || s == "be") ? Endian::Big : Endian::Little;
}

std::optional<Confidence> parse_tier(const std::string& s) {
    if (s == "magic") return Confidence::Magic;
    if (s == "structural") return Confidence::Structural;
    if (s == "consistent") return Confidence::Consistent;
    if (s == "verified") return Confidence::Verified;
    return std::nullopt;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::string h;
    for (char c : hex)
        if (!std::isspace(static_cast<unsigned char>(c))) h += c;
    if (h.size() % 2 != 0) throw std::runtime_error("magic hex must have even length: '" + hex + "'");
    std::vector<uint8_t> out;
    for (size_t i = 0; i < h.size(); i += 2) {
        auto nib = [&](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            c = static_cast<char>(std::tolower(c));
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            throw std::runtime_error("bad hex digit in magic");
        };
        out.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    }
    return out;
}

// Load one signature from a parsed table. Throws std::runtime_error on any
// structural problem so the caller can record it and skip the file.
Signature load_one(const toml::table& tbl) {
    Signature sig;
    sig.name = tbl["name"].value_or<std::string>("");
    if (sig.name.empty()) throw std::runtime_error("missing 'name'");
    sig.category = tbl["category"].value_or<std::string>("");
    sig.short_sig = tbl["short"].value_or(false);
    sig.magic_offset = static_cast<size_t>(tbl["magic_offset"].value_or<int64_t>(0));
    sig.size_clamp = tbl["size_clamp"].value_or(false);
    sig.coalesce = tbl["coalesce"].value_or(false);

    // magic patterns
    const auto* magics = tbl["magic"].as_array();
    if (!magics || magics->empty()) throw std::runtime_error("no [[magic]] entries");
    for (const auto& node : *magics) {
        const auto* mt = node.as_table();
        if (!mt) throw std::runtime_error("[[magic]] entry is not a table");
        MagicPattern mp;
        mp.endian = parse_endian((*mt)["endian"].value_or<std::string>("little"));
        if (auto ascii = (*mt)["ascii"].value<std::string>()) {
            for (char c : *ascii) mp.bytes.push_back(static_cast<uint8_t>(c));
        } else if (auto hex = (*mt)["hex"].value<std::string>()) {
            mp.bytes = hex_to_bytes(*hex);
        } else {
            throw std::runtime_error("[[magic]] needs 'ascii' or 'hex'");
        }
        if (mp.bytes.empty()) throw std::runtime_error("empty magic");
        sig.magics.push_back(std::move(mp));
    }

    // declarative layout
    if (auto st = tbl["struct"].value<std::string>()) sig.layout = Layout::parse(*st);

    // valid variable names for constraint/size validation
    std::unordered_set<std::string> known{"_avail", "_offset"};
    for (const auto& n : sig.layout.int_field_names()) known.insert(n);
    auto check_vars = [&](const ExprPtr& e, const char* where) {
        for (const auto& v : expr_vars(*e))
            if (!known.count(v))
                throw std::runtime_error(std::string(where) + " references unknown field '" + v + "'");
    };

    // constraints
    if (const auto* arr = tbl["constraints"].as_array()) {
        for (const auto& node : *arr) {
            auto s = node.value<std::string>();
            if (!s) throw std::runtime_error("constraint is not a string");
            ExprPtr e = parse_expr(*s);
            check_vars(e, "constraint");
            sig.constraints.push_back(std::move(e));
        }
    }

    // soft constraints (validity, not identity): failing one downgrades the hit
    // to `magic` tier instead of rejecting it. See Signature::soft_constraints.
    if (const auto* arr = tbl["soft_constraints"].as_array()) {
        for (const auto& node : *arr) {
            auto s = node.value<std::string>();
            if (!s) throw std::runtime_error("soft_constraint is not a string");
            ExprPtr e = parse_expr(*s);
            check_vars(e, "soft_constraint");
            sig.soft_constraints.push_back(std::move(e));
        }
    }
    sig.soft_evidence = tbl["soft_evidence"].value_or(
        std::string("identifying bytes found, but one header value is outside the expected range"));

    // size expression
    if (auto s = tbl["size"].value<std::string>()) {
        sig.size_expr = parse_expr(*s);
        check_vars(sig.size_expr, "size");
    }

    // confidence tier when constraints pass
    if (auto c = tbl["confidence"].value<std::string>()) {
        auto t = parse_tier(*c);
        if (!t) throw std::runtime_error("unknown confidence tier '" + *c + "'");
        sig.pass_tier = *t;
    } else {
        sig.pass_tier = (!sig.constraints.empty() || !sig.layout.empty()) ? Confidence::Structural
                                                                          : Confidence::Magic;
    }

    // validator
    if (auto v = tbl["validator"].value<std::string>()) {
        sig.validator_name = *v;
        sig.validator = find_validator(*v);
        if (!sig.validator) throw std::runtime_error("unknown validator '" + *v + "'");
    }

    // doc metadata
    if (const auto* doc = tbl["doc"].as_table()) {
        sig.description = (*doc)["description"].value_or<std::string>("");
        sig.vendor = (*doc)["vendor"].value_or<std::string>("");
        if (const auto* refs = (*doc)["references"].as_array()) {
            for (const auto& node : *refs) {
                if (const auto* rt = node.as_table())
                    sig.references.push_back({(*rt)["title"].value_or<std::string>(""),
                                              (*rt)["url"].value_or<std::string>("")});
            }
        }
        if (const auto* lims = (*doc)["limitations"].as_array()) {
            for (const auto& node : *lims)
                if (auto s = node.value<std::string>()) sig.limitations.push_back(*s);
        }
    }

    return sig;
}

// Pull every signature out of one parsed TOML document into `result`. A document
// holds either one signature (top-level keys) or many (a [[signature]] array, as
// the generated Wave-2 set uses). Bad entries are recorded and skipped, not fatal.
void extract_signatures(const toml::table& tbl, const std::string& name, LoadResult& result) {
    if (const auto* arr = tbl["signature"].as_array()) {
        for (const auto& node : *arr) {
            const auto* st = node.as_table();
            if (!st) continue;
            try {
                result.signatures.push_back(load_one(*st));
            } catch (const std::exception& e) {
                result.errors.push_back(name + " [entry]: " + e.what());
            }
        }
    } else {
        try {
            result.signatures.push_back(load_one(tbl));
        } catch (const std::exception& e) {
            result.errors.push_back(name + ": " + e.what());
        }
    }
}

}  // namespace

LoadResult load_signatures(const std::string& dir) {
    LoadResult result;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        result.errors.push_back("file-recognition rule folder not found: " + dir);
        return result;
    }

    std::vector<fs::path> paths;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".toml")
            paths.push_back(entry.path());
    }
    std::sort(paths.begin(), paths.end());  // deterministic load order

    for (const auto& p : paths) {
        toml::table tbl;
        try {
            tbl = toml::parse_file(p.string());
        } catch (const std::exception& e) {
            result.errors.push_back(p.filename().string() + ": " + e.what());
            continue;
        }
        extract_signatures(tbl, p.filename().string(), result);
    }
    return result;
}

LoadResult load_signatures_from_memory(std::span<const EmbeddedToml> docs) {
    LoadResult result;
    for (const auto& d : docs) {
        toml::table tbl;
        try {
            tbl = toml::parse(std::string_view(d.data, d.size), std::string_view(d.name));
        } catch (const std::exception& e) {
            result.errors.push_back(std::string(d.name) + ": " + e.what());
            continue;
        }
        extract_signatures(tbl, d.name, result);
    }
    return result;
}

size_t drop_redundant_generic_signatures(std::vector<Signature>& lower,
                                         const std::vector<Signature>& authoritative) {
    // Claimed = (magic_offset, magic bytes) of every signature that validates its
    // own magic (has a C++ validator). Those are authoritative for that magic.
    std::set<std::pair<size_t, std::vector<uint8_t>>> claimed;
    for (const auto& s : authoritative) {
        if (!s.validator) continue;
        for (const auto& m : s.magics) claimed.insert({s.magic_offset, m.bytes});
    }
    if (claimed.empty()) return 0;

    auto redundant = [&](const Signature& s) {
        // Only a pure magic match with nothing of its own to contribute: no
        // validator and no hard constraints. Every magic must be claimed, so a
        // sig that also matches something novel is kept.
        if (s.validator || !s.constraints.empty() || s.magics.empty()) return false;
        for (const auto& m : s.magics)
            if (!claimed.count({s.magic_offset, m.bytes})) return false;
        return true;
    };

    size_t before = lower.size();
    lower.erase(std::remove_if(lower.begin(), lower.end(), redundant), lower.end());
    return before - lower.size();
}

}  // namespace ft

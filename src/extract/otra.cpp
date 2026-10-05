// otra.cpp — Artosyn OTRA firmware image extraction. See otra.hpp.
//
// Segmented: one raw image per partition = concat of its LZO1X-decompressed
// segments (data_len compressed -> flash_len decompressed, no per-segment CRC).
// Flat: the body (0x220..EOF) is a raw flash image; write it whole. Either way the
// output is re-identified when moria recurses into the extraction directory.
#include "extract/otra.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "extract/lzo1x.hpp"
#include "extract/safepath.hpp"
#include "otra_format.hpp"

namespace ft {

namespace {

constexpr uint64_t kMaxPart = uint64_t(64) << 20;  // 64 MiB cap on one decoded partition

std::string sanitize(const std::string& name) {
    std::string s;
    for (char c : name) {
        unsigned char u = static_cast<unsigned char>(c);
        s += (u == '.' || u == '_' || u == '-' || (u >= '0' && u <= '9') ||
              (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z'))
                 ? c
                 : '_';
    }
    return s;
}

}  // namespace

bool extract_otra(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                  Extracted& out) {
    out.offset = f.offset;
    out.type = "otra";
    out.root = subdir;

    auto ho = otra::parse_otra(r, f.offset);
    if (!ho) {
        out.status = "error:header";
        return true;
    }
    const otra::Header& h = *ho;
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }

    auto tables = otra::parse_otra_tables(r, f.offset, h);

    // Flat subtype: no populated tables — the body is a raw flash image. Write it
    // whole so downstream carving / recursion can work on it.
    if (!tables.segmented) {
        const size_t body_off = f.offset + otra::kHeaderEnd;
        auto body = r.bytes(body_off, r.size() - body_off);
        if (!body) {
            out.status = "error:body";
            return true;
        }
        std::vector<uint8_t> data(body->begin(), body->end());
        if (!root.write_file(subdir + "/flash.bin", data, 0644)) {
            out.status = "error:write";
            return true;
        }
        out.files++;
        out.bytes += data.size();
        out.consumed = r.size() - f.offset;
        out.status = "ok";
        return true;
    }

    // Segmented subtype: one raw partition image per partition that carries segments.
    bool any_fail = false;
    size_t part_idx = 0;
    for (const auto& p : tables.parts) {
        const size_t idx = part_idx++;
        auto sel = otra::segments_of(p, tables.segs);
        if (sel.empty()) continue;  // inactive B-slot / no payload in this image

        uint64_t total = 0;
        for (const auto* s : sel) total += s->flash_len;
        if (total == 0 || total > kMaxPart) {
            any_fail = true;
            out.warnings.push_back(p.name + ": implausible size, skipped");
            continue;
        }

        std::vector<uint8_t> blob;
        blob.reserve(static_cast<size_t>(total));
        bool ok = true;
        for (const auto* s : sel) {
            auto src = r.bytes(s->file_off, s->data_len);
            if (!src) { ok = false; break; }
            std::vector<uint8_t> dec(static_cast<size_t>(s->flash_len));
            size_t got = 0;
            if (!lzo1x_decompress_safe(src->data(), src->size(), dec.data(), dec.size(), &got) ||
                got != s->flash_len) {
                ok = false;
                break;
            }
            blob.insert(blob.end(), dec.begin(), dec.end());
        }

        std::string name = sanitize(p.name);
        if (name.empty()) name = "part";
        char pfx[8];
        std::snprintf(pfx, sizeof(pfx), "%02zu_", idx);
        std::string fname = std::string(pfx) + name + ".bin";

        if (!ok) {
            any_fail = true;
            out.warnings.push_back(p.name + ": LZO segment decode failed");
            continue;  // don't write a truncated/corrupt partition image
        }
        if (!root.write_file(subdir + "/" + fname, blob, 0644)) {
            out.status = "error:write";
            return true;
        }
        out.files++;
        out.bytes += blob.size();
    }

    out.consumed = r.size() - f.offset;
    if (out.files == 0)
        out.status = "error:no-partitions";
    else
        out.status = any_fail ? "partial" : "ok";
    return true;
}

}  // namespace ft

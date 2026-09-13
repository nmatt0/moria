// vbmeta.cpp — AVB vbmeta artifact extraction. See vbmeta.hpp.
#include "extract/vbmeta.hpp"

#include <cstdint>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {
// AvbVBMetaImageHeader field offsets (big-endian), header is 256 bytes.
constexpr size_t kAuthSize = 12;
constexpr size_t kPubKeyOff = 64;
constexpr size_t kPubKeySize = 72;
constexpr size_t kDescOff = 96;
constexpr size_t kDescSize = 104;
constexpr size_t kHeaderSize = 256;

bool write_slice(const Reader& r, size_t at, uint64_t len, SafeRoot& root, const std::string& rel,
                 Extracted& out) {
    if (len == 0) return true;
    auto b = r.bytes(at, len);
    if (!b) {
        out.warnings.push_back(rel + ": out of range");
        return true;
    }
    std::vector<uint8_t> data(b->begin(), b->end());
    if (!root.write_file(rel, data, 0644)) {
        out.status = "error:write";
        return false;
    }
    out.files++;
    out.bytes += data.size();
    return true;
}
}  // namespace

bool extract_vbmeta(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out) {
    out.offset = f.offset;
    out.type = "vbmeta";
    out.root = subdir;

    const size_t off = f.offset;
    auto auth = r.at<uint64_t>(off + kAuthSize, Endian::Big);
    auto pk_off = r.at<uint64_t>(off + kPubKeyOff, Endian::Big);
    auto pk_size = r.at<uint64_t>(off + kPubKeySize, Endian::Big);
    auto desc_off = r.at<uint64_t>(off + kDescOff, Endian::Big);
    auto desc_size = r.at<uint64_t>(off + kDescSize, Endian::Big);
    if (!auth || !pk_off || !pk_size || !desc_off || !desc_size) {
        out.status = "error:bad-header";
        return true;
    }
    // The auxiliary block follows the header + authentication block.
    const size_t aux_base = off + kHeaderSize + *auth;

    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    if (!write_slice(r, aux_base + *pk_off, *pk_size, root, subdir + "/vbmeta-pubkey.bin", out))
        return true;
    if (!write_slice(r, aux_base + *desc_off, *desc_size, root, subdir + "/vbmeta-descriptors.bin",
                     out))
        return true;
    if (out.status.empty()) out.status = out.files ? "ok" : "partial";
    return true;
}

}  // namespace ft

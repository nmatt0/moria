// descramble.cpp — see descramble.hpp.
#include "extract/descramble.hpp"

#include "deobfuscate/scheme.hpp"

namespace ft {

bool extract_descramble(const Reader& r, const Finding& f, SafeRoot& root,
                        const std::string& subdir, Extracted& out) {
    out.offset = f.offset;
    out.type = f.type;
    out.root = subdir;

    auto res = descramble(r, static_cast<size_t>(f.offset), f.type);
    if (!res || res->data.empty()) {
        // Header matched but no working key / plaintext failed validation: the
        // payload is present but not offline-decryptable with what we hold.
        out.status = "error:no-key";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    if (root.write_file(subdir + "/descrambled.bin", res->data, 0644)) {
        out.files++;
        out.bytes += res->data.size();
        out.consumed = res->total_span;  // let the driver claim header+ciphertext
        out.warnings.push_back("restored scrambled data with " + res->scheme + " (" + res->cipher +
                               "; key: " + res->key_desc + "; restored file type: " +
                               res->validated + ")");
        out.status = "ok";
    } else {
        out.status = "error:write";
    }
    return true;
}

}  // namespace ft

// spiffs.cpp — SPIFFS extraction entry point. See extract/spiffs.hpp.
#include "extract/spiffs.hpp"

#include "extract/safepath.hpp"
#include "spiffs_parse.hpp"

namespace ft {

bool extract_spiffs(const Reader& r, const Finding& f, SafeRoot& root,
                    const std::string& subdir, Extracted& out) {
    out.offset = f.offset;
    out.type = "spiffs";
    out.root = subdir;

    SpiffsGeom g = spiffs_infer(r);
    if (!g.ok) {
        out.status = "error:no-geometry";
        return true;
    }
    SpiffsStats st;
    if (!spiffs_extract(r, g, root, subdir, st)) {
        out.status = "error:extract";
        return true;
    }
    out.files = st.files;
    out.bytes = st.bytes;
    out.consumed = r.size();
    out.status = st.truncated ? "partial" : "ok";
    if (st.truncated) out.warnings.push_back("some objects had missing data pages");
    return true;
}

}  // namespace ft

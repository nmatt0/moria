// littlefs.cpp — LittleFS extraction entry point. See extract/littlefs.hpp.
#include "extract/littlefs.hpp"

#include "extract/safepath.hpp"
#include "littlefs_parse.hpp"

namespace ft {

bool extract_littlefs(const Reader& r, const Finding& f, SafeRoot& root,
                      const std::string& subdir, Extracted& out) {
    out.offset = f.offset;
    out.type = "littlefs";
    out.root = subdir;

    LfsSuper s = lfs_read_super(r, f.offset);
    if (!s.ok) {
        out.status = "error:bad-superblock";
        return true;
    }
    LfsStats st;
    if (!lfs_extract(r, s, root, subdir, st)) {
        out.status = "error:extract";
        return true;
    }
    out.files = st.files;
    out.dirs = st.dirs;
    out.symlinks = 0;
    out.bytes = st.bytes;
    out.consumed = static_cast<size_t>(s.block_size) * s.block_count;
    out.status = (st.crc_fail || st.truncated) ? "partial" : "ok";
    if (st.crc_fail) out.warnings.push_back("some metadata/data failed CRC");
    if (st.truncated) out.warnings.push_back("walk capped (depth/count/size guard)");
    return true;
}

}  // namespace ft

// littlefs.cpp — LittleFS identification validator. See littlefs.hpp.
#include "validators/littlefs.hpp"

#include <string>

#include "littlefs_parse.hpp"

namespace ft {

bool validate_littlefs(ValidatorCtx& ctx) {
    // ctx.offset is the superblock (block 0) start: the magic "littlefs" matched at
    // offset 8, and magic_offset=8 sets ctx.offset to the structure start.
    LfsSuper s = lfs_read_super(ctx.reader, ctx.offset);
    if (!s.ok) return false;

    Finding& out = ctx.out;
    out.type = "littlefs";
    out.category = "filesystem";
    out.endian = Endian::Little;
    out.version = std::to_string(s.version >> 16) + "." + std::to_string(s.version & 0xffff);
    // The finding spans the whole filesystem so interior metadata/data isn't
    // re-detected as peer findings.
    out.size = static_cast<size_t>(s.block_size) * s.block_count;
    out.set_confidence(Confidence::Verified,
                       "LittleFS v" + out.version + " superblock, CRC verified (" +
                           std::to_string(s.block_count) + " x " +
                           std::to_string(s.block_size) + "-byte blocks)");
    return true;
}

}  // namespace ft

// android_boot.cpp — see android_boot.hpp. Mirrors the header math in
// src/extract/android_boot.cpp (kept in sync with it).
#include "validators/android_boot.hpp"

#include <cstdint>
#include <optional>

#include "reader.hpp"

namespace ft {

namespace {
uint64_t roundup(uint64_t x, uint64_t n) { return n ? ((x + n - 1) / n) * n : x; }
}  // namespace

bool validate_android_boot(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const uint64_t base = ctx.offset;
    auto u32 = [&](uint64_t o) { return r.at<uint32_t>(o, Endian::Little); };

    auto hv = u32(base + 40);  // header_version @40 for all versions
    if (!hv) return true;
    // Real boot images are version 0-4. The "ANDROID!" magic also occurs as a
    // bootloader string literal; a garbage header_version is the giveaway.
    if (*hv > 4) return false;

    uint64_t end = 0;  // bytes from base to the end of the last component
    if (*hv >= 3) {
        // v3/v4: fixed 4096-byte page, kernel + ramdisk only (init_boot: kernel=0).
        const uint64_t page = 4096;
        auto ksize = u32(base + 8), rsize = u32(base + 12);
        if (!ksize || !rsize) return true;
        end = page + roundup(*ksize, page) + roundup(*rsize, page);
    } else {
        // v0/v1/v2: page_size @36; kernel/ramdisk/second[/recovery_dtbo][/dtb].
        auto ksize = u32(base + 8), rsize = u32(base + 16), ssize = u32(base + 24), page = u32(base + 36);
        if (!ksize || !rsize || !ssize || !page || *page == 0 || (*page & (*page - 1))) return true;
        const uint64_t p = *page;
        end = p + roundup(*ksize, p) + roundup(*rsize, p) + roundup(*ssize, p);
        if (*hv >= 1) {
            if (auto rd = u32(base + 1632)) end += roundup(*rd, p);
        }
        if (*hv >= 2) {
            if (auto dtb = u32(base + 1648)) end += roundup(*dtb, p);
        }
    }
    if (end == 0) return true;

    // A real boot image's declared layout fits in the bytes we have (a boot.img
    // embedded in a flash dump, or one that is the whole file, always fits). A
    // header claiming far more than the file is a false positive on the magic
    // (e.g. an "ANDROID!" string in a bootloader) — reject rather than clamp the
    // span to EOF, which would otherwise swallow the real kernel/rootfs after it.
    const uint64_t avail = r.size() > base ? r.size() - base : 0;
    if (end > avail) return false;
    if (end > ctx.out.size) ctx.out.size = static_cast<size_t>(end);
    // Whole declared layout present in-file -> the structure is internally
    // consistent, not just a magic + a plausible size field.
    ctx.out.set_confidence(Confidence::Consistent, "declared boot image layout fits in the file");
    return true;
}

}  // namespace ft

// android_boot.cpp — Android boot image splitting. See android_boot.hpp.
//
// Header v0-2 (variable page_size @36): kernel_size@8, ramdisk_size@16,
// second_size@24, page_size@36, header_version@40; v1 adds recovery_dtbo_size@
// 1632, v2 adds dtb_size@1648. Header v3-4 (fixed 4096 page): kernel_size@8,
// ramdisk_size@12, header_version@40. Components follow the header, each padded
// up to a page: kernel first (at page 1), then ramdisk, second, recovery_dtbo,
// dtb in order.
#include "extract/android_boot.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint64_t MAX_COMPONENT = uint64_t(1) << 30;  // 1 GiB sanity cap

std::optional<uint32_t> u32(const Reader& r, uint64_t o) { return r.at<uint32_t>(o, Endian::Little); }

uint64_t roundup(uint64_t x, uint64_t n) { return n ? ((x + n - 1) / n) * n : x; }

// Write one component [off, off+size) as `name`. Advances nothing; returns true
// if a (possibly empty) component was handled without a hard read error.
void write_component(const Reader& r, uint64_t abs_off, uint64_t size, const std::string& subdir,
                     const char* name, SafeRoot& root, Extracted& out, bool& truncated) {
    if (size == 0) return;
    if (size > MAX_COMPONENT) { truncated = true; return; }
    auto d = r.bytes(static_cast<size_t>(abs_off), static_cast<size_t>(size));
    if (!d) { truncated = true; return; }
    std::vector<uint8_t> data(d->begin(), d->end());
    if (root.write_file(subdir + "/" + name, data, 0644)) {
        out.files++;
        out.bytes += data.size();
    } else {
        out.warnings.push_back(std::string("write failed: ") + name);
    }
}

}  // namespace

bool extract_android_boot(const Reader& r, const Finding& f, SafeRoot& root,
                          const std::string& subdir, Extracted& out) {
    out.offset = f.offset;
    out.type = "android_boot";
    out.root = subdir;
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    const uint64_t base = f.offset;
    auto hv = u32(r, base + 40);  // header_version at offset 40 for all versions
    if (!hv) {
        out.status = "error:bad-header";
        return true;
    }
    bool truncated = false;

    if (*hv >= 3) {
        // v3/v4: fixed 4096-byte pages, only kernel + ramdisk in the boot image.
        const uint64_t page = 4096;
        auto ksize = u32(r, base + 8);
        auto rsize = u32(r, base + 12);
        if (!ksize || !rsize) { out.status = "error:bad-header"; return true; }
        uint64_t off = base + page;  // header occupies exactly one page
        write_component(r, off, *ksize, subdir, "kernel", root, out, truncated);
        off += roundup(*ksize, page);
        write_component(r, off, *rsize, subdir, "ramdisk", root, out, truncated);
    } else {
        // v0/v1/v2: page_size from the header; kernel/ramdisk/second[/recovery_dtbo/dtb].
        auto ksize = u32(r, base + 8);
        auto rsize = u32(r, base + 16);
        auto ssize = u32(r, base + 24);
        auto page = u32(r, base + 36);
        if (!ksize || !rsize || !ssize || !page || *page == 0 || (*page & (*page - 1))) {
            out.status = "error:bad-header";
            return true;
        }
        const uint64_t p = *page;
        uint64_t off = base + p;  // kernel starts at page 1
        write_component(r, off, *ksize, subdir, "kernel", root, out, truncated);
        off += roundup(*ksize, p);
        write_component(r, off, *rsize, subdir, "ramdisk", root, out, truncated);
        off += roundup(*rsize, p);
        write_component(r, off, *ssize, subdir, "second", root, out, truncated);
        off += roundup(*ssize, p);
        if (*hv >= 1) {
            auto rd = u32(r, base + 1632);  // recovery_dtbo_size
            if (rd) {
                write_component(r, off, *rd, subdir, "recovery_dtbo", root, out, truncated);
                off += roundup(*rd, p);
            }
        }
        if (*hv >= 2) {
            auto dtb = u32(r, base + 1648);  // dtb_size
            if (dtb) write_component(r, off, *dtb, subdir, "dtb", root, out, truncated);
        }
    }

    if (out.files == 0) {
        // A valid boot header whose declared kernel/ramdisk aren't present in the
        // available bytes: a stub (e.g. Fire TV microloader) or an embedded header
        // whose payload lives elsewhere, not a normal extraction failure.
        out.status = "error:no-components";
        if (truncated)
            out.warnings.push_back(
                "listed parts extend past the available data; this may be a boot stub");
        return true;
    }
    out.status = truncated ? "partial" : "ok";
    return true;
}

}  // namespace ft

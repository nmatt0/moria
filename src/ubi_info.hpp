// ubi_info.hpp — identify-time UBI structure: extent + volume table.
//
// A UBI image is a series of physical erase blocks (PEBs), each with an "UBI#"
// erase-count header and an "UBI!" volume-id header; a special layout volume
// (id 0x7fffefff) holds the volume table naming every volume. This reads that
// table (without extracting) so moria can present a UBI as one region with its
// named volumes as children, instead of thousands of per-PEB findings.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "finding.hpp"
#include "reader.hpp"

namespace ft {

struct UbiVolume {
    uint32_t vol_id = 0;
    std::string name;
    bool is_static = false;   // vol_type 2 = static, 1 = dynamic
    uint64_t size = 0;        // reserved bytes (reserved_pebs * usable LEB size)
    std::string content;      // sniffed content magic: squashfs/uimage/ubifs/fit/...
};

struct UbiInfo {
    bool ok = false;
    size_t start = 0;         // UBI extent within the image
    size_t end = 0;
    uint64_t peb = 0;         // physical erase-block size
    std::vector<UbiVolume> volumes;
    std::vector<uint32_t> peb_vol;  // vol_id of PEB k (k = (off-start)/peb); 0xFFFFFFFF = free/layout

    // Which volume owns the byte `off` (an image offset), or 0xFFFFFFFF.
    uint32_t volume_at(size_t off) const {
        if (!peb || off < start || off >= end) return 0xFFFFFFFF;
        size_t k = (off - start) / peb;
        return k < peb_vol.size() ? peb_vol[k] : 0xFFFFFFFF;
    }
};

// Parse the UBI starting at `base` (an "UBI#" EC header). Returns ok=false if it
// does not look like a UBI or the volume table can't be read.
UbiInfo parse_ubi(const Reader& r, size_t base);

// Replace each UBI's swarm of per-PEB ubi/ubifs findings (and its interior
// structure) with ONE `ubi` finding spanning the whole volume, carrying the
// named volumes from the volume table as `members`. Embedded crypto findings
// (keys/certs) inside the UBI are kept (they nest under it). `all` (-A) disables it,
// leaving the raw per-PEB findings.
std::vector<Finding> enrich_ubi_findings(const Reader& r, std::vector<Finding> findings, bool all);

}  // namespace ft

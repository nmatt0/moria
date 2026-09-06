// fit.hpp — U-Boot FIT (Flattened Image Tree) subimage extraction.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

// A FIT is a Flattened Device Tree (FDT) blob whose root has an `/images` node
// containing subimage nodes (kernel / ramdisk / fdt / ...). Each subimage's
// payload is either embedded in a `data` property or stored externally
// (`data-offset`+`data-size` relative to the aligned end of the FDT, or an
// absolute `data-position`). We split each payload out and decompress it per its
// `compression` property.
bool extract_fit(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

// True if the FDT blob at `off` is a FIT (its root device-tree node contains an
// `/images` subnode). Used by the dtb signature validator to reclassify a plain
// DTB match as a FIT so the extractor is dispatched. When it returns true and
// `span` is non-null, `*span` is set to the total FIT byte span from `off`: the
// FDT `totalsize` for an embedded-data FIT, or the end of the last external data
// blob for an external-data FIT — so the finding can claim its appended payloads.
bool fdt_is_fit(const Reader& r, size_t off, uint64_t* span = nullptr);

}  // namespace ft

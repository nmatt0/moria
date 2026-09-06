// resolve.hpp — deterministic conflict resolution over validated candidates.
// Three passes: deterministic sort, overlap/same-offset elimination (losers
// retained in the winner's `also_matched`), size inference. The sort is a total
// order, so a given input always resolves to the same output (no random tiebreak).
#pragma once

#include <set>
#include <string>
#include <vector>

#include "finding.hpp"

namespace ft {

// `coalesce_types` names types whose consecutive same-type findings should be
// merged into one region (per-node formats like jffs2/ubi that would otherwise
// emit thousands of findings).
std::vector<Finding> resolve(std::vector<Finding> candidates, size_t file_size,
                             const std::set<std::string>& coalesce_types);

// Merge filesystem/container findings into coverage regions, bridging gaps up to
// `gap` bytes. A per-node flash filesystem (UBI/UBIFS) appears as many small
// findings interleaved with the compressed data nodes it holds; merging with a
// gap that spans the erase-block grid recovers the true region extent. Used both
// to suppress interior compressed streams and to keep the entropy/unidentified-
// region pass from re-reporting a filesystem's interior. Input assumed sorted by
// offset; returns [start,end) spans.
std::vector<std::pair<size_t, size_t>> container_regions(const std::vector<Finding>& findings,
                                                         size_t gap = 512 * 1024);

// Suppression of interior findings. Any finding strictly enclosed by a
// filesystem/container finding is interior noise: the container's own extractor
// owns everything inside it, so those leaked hits must not appear as peer
// top-level findings or drive redundant/failed extractions. This covers a flash
// filesystem's compressed data nodes (UBI/UBIFS xz/gzip/lzo), an android_boot's
// kernel/ramdisk, and the spurious xz/elf/zip magic hits that land inside
// compressed data. Strict containment never drops the enclosing container.
// `all` (from -A/--all) disables it. `*dropped` (optional) receives the count.
std::vector<Finding> suppress_interior_findings(std::vector<Finding> findings, bool all,
                                                size_t* dropped = nullptr);

}  // namespace ft

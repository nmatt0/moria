// archives.hpp — list archive members (names + sizes) without extracting content.
// Parses the directory structures of tar / cpio (newc) / zip only. Bounded by
// MAX_MEMBERS; sets `members_truncated` when hit. Powers --list.
#pragma once

#include "finding.hpp"
#include "reader.hpp"

namespace ft {

constexpr size_t MAX_MEMBERS = 5000;

// Populate f.members for a tar/cpio/zip finding at f.offset. No-op for others.
void list_members(const Reader& r, Finding& f);

}  // namespace ft

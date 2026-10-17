// reiserfs.hpp — ReiserFS (3.5 / 3.6) read-only extractor.
//
// Walks the S+ tree from the superblock's root block, collects every leaf item,
// and rebuilds the directory hierarchy under a SafeRoot: regular files (direct
// tails + indirect block lists, holes honored), directories, and symlinks. Item
// key format (v1 "old" / v2 "new") is read per item from ih_version, so a 3.6
// image that mixes a v2 stat-data item with a v1 directory item in the same
// object is handled. No journal replay, no write support, no mount, no sudo
// (unlike mount/debugreiserfs). Every read goes through the bounds-checked
// Reader; a truncated or corrupt image yields a partial result, never OOB.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_reiserfs(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                      Extracted& out);

// Parse-only driver for fuzzing (fuzz/fuzz_reiserfs.cpp): walks the S+ tree from
// a superblock at `sb_off` and exercises the item/dir/content byte parsing with
// no filesystem writes. Every read is bounds-checked, so any input is safe.
size_t reiserfs_probe(const Reader& r, size_t sb_off);

}  // namespace ft

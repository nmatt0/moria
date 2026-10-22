// nilfs2.hpp — NILFS2 (log-structured) read-only extractor.
//
// NILFS2 is a log-structured filesystem: the live tree is reached through the
// latest checkpoint, not a fixed inode table. This extractor picks the newer of
// the two superblocks, follows its last partial segment to the super root, reads
// the DAT (disk address translation), cpfile (checkpoints) and, via the last
// checkpoint, the ifile (inode file); then it walks the root directory and
// rebuilds regular files, directories and symlinks under a SafeRoot. Block
// mappings are NILFS2 bmaps (inline "direct" or a B-tree); non-DAT pointers are
// virtual block numbers resolved through the DAT. No GC, no roll-forward
// recovery, no write support, no mount (unlike the kernel driver). Every read
// goes through the bounds-checked Reader, so a truncated or corrupt image yields
// a partial result, never an out-of-bounds access.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_nilfs2(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                    Extracted& out);

// Parse-only driver for fuzzing (fuzz/fuzz_nilfs2.cpp): runs the whole read chain
// (superblock, super root, DAT, cpfile, ifile, directory walk, file/content
// block mapping) with no filesystem writes. Every read is bounds-checked.
size_t nilfs2_probe(const Reader& r, size_t base);

}  // namespace ft

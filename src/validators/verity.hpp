#pragma once
#include "signature.hpp"
namespace ft {
// Confirm a dm-verity superblock and size the finding to its hash metadata
// (superblock block + the hash tree, computed from data_blocks and the block/
// hash sizes). Sets the hash algorithm as the label. Match -> `consistent`.
bool validate_verity(ValidatorCtx& ctx);
}  // namespace ft

// partition.hpp — GPT and MBR/DOS partition-table validators.
//
// Both identify a partition table and emit each partition as a Member of the
// finding (name/type/offset/size), turning a raw disk image into a labeled
// region map. The filesystems inside the partitions are identified and extracted
// by moria's normal scan/extract pipeline (the table finding is sized to just the
// table metadata, so it does not enclose or suppress them). No extractor.
#pragma once

#include "signature.hpp"

namespace ft {

// GPT: magic "EFI PART" at the LBA1 header. Verifies the header + entry-array
// CRC32 (verified tier), decodes partition type GUIDs to names, reports each
// partition as a member. Rejects a backup header (my_lba != 1).
bool validate_gpt(ValidatorCtx& ctx);

// MBR/DOS: boot signature 0x55AA at 0x1FE. Validates the four primary entries
// (boot flags, sane LBA ranges), decodes type bytes to names, walks the extended
// partition chain. Rejects a bare protective MBR (a single 0xEE spanning the
// disk) so the GPT owns the map. FP-guarded (0x55AA is a common trailer).
bool validate_mbr(ValidatorCtx& ctx);

}  // namespace ft

// legacy_fs.hpp — validated identify-only for a batch of legacy / less-common
// block filesystems: NILFS2, Minix (v1/v2/v3), ReiserFS, UFS/FFS, APFS, LogFS.
//
// Each parses just enough of the superblock to give an honest validated verdict
// (promoting these out of weak --broad magic-only hits). No extraction — these
// are rare in IoT/embedded and a clean "this is X" is the whole value.
#pragma once

#include "signature.hpp"

namespace ft {

bool validate_nilfs2(ValidatorCtx& ctx);    // magic 0x3434 @ superblock+6 (SB at 1024)
bool validate_minix(ValidatorCtx& ctx);     // v1/v2 magic @ SB+0x10, v3 @ SB+0x18 (SB at 1024)
bool validate_reiserfs(ValidatorCtx& ctx);  // "ReIsEr*Fs" @ SB+0x34
bool validate_ufs(ValidatorCtx& ctx);       // 0x00011954 / 0x19540119 @ SB+0x55C (LE/BE)
bool validate_apfs(ValidatorCtx& ctx);      // "NXSB" @ container-superblock+0x20
bool validate_logfs(ValidatorCtx& ctx);     // 64-bit magic 0x7a3a8e5cb9d5bf67

}  // namespace ft

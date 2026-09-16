// legacy_fs.cpp — identify-only superblock validators. See legacy_fs.hpp.
//
// Only Minix is round-trip tested against a real maker (mkfs.minix); the others
// are implemented from the documented on-disk superblock layouts (Linux kernel
// headers / published specs) and covered by synthetic fixtures. Validation is
// deliberately conservative: enough field checks to reject the weak-magic false
// positives (NILFS2's 2-byte 0x3434, Minix's 2-byte magics) without over-
// constraining a real image on a field a variant might set differently.
#include "validators/legacy_fs.hpp"

#include <cstdint>
#include <string>
#include <vector>

#include "crc32.hpp"

namespace ft {

namespace {

uint16_t u16le(const Reader& r, size_t o) {
    auto v = r.at<uint16_t>(o, Endian::Little);
    return v ? *v : 0;
}
uint32_t u32(const Reader& r, size_t o, Endian e) {
    auto v = r.at<uint32_t>(o, e);
    return v ? *v : 0;
}
uint64_t u64(const Reader& r, size_t o, Endian e) {
    auto v = r.at<uint64_t>(o, e);
    return v ? *v : 0;
}

bool is_pow2(uint64_t x) { return x != 0 && (x & (x - 1)) == 0; }

}  // namespace

// NILFS2: superblock at byte 1024; s_magic (0x3434) at +6. The magic is only two
// bytes, so identity rests on the superblock CRC32 (s_sum @ +0x10, seeded with
// s_crc_seed @ +0x0C, over s_bytes with s_sum zeroed) — matching Linux
// crc32_le == moria crc32_raw. The CRC makes this verified and FP-proof.
bool validate_nilfs2(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t sb = ctx.offset + 1024;
    if (u16le(r, sb + 6) != 0x3434) return false;
    uint16_t s_bytes = u16le(r, sb + 8);
    uint32_t log_bs = u32(r, sb + 0x14, Endian::Little);
    if (s_bytes < 0x30 || s_bytes > 1024) return false;
    if (log_bs > 6) return false;  // block size 2^(10+shift), up to 64 KiB

    uint32_t seed = u32(r, sb + 0x0C, Endian::Little);
    uint32_t stored = u32(r, sb + 0x10, Endian::Little);
    auto span = r.bytes(sb, s_bytes);
    if (!span) return false;
    std::vector<uint8_t> buf(span->begin(), span->end());
    buf[0x10] = buf[0x11] = buf[0x12] = buf[0x13] = 0;  // zero s_sum for the CRC
    if (crc32_raw(seed, buf) != stored) return false;

    Finding& out = ctx.out;
    out.type = "nilfs2";
    out.category = "filesystem";
    out.endian = Endian::Little;
    uint64_t dev_size = u64(r, sb + 0x20, Endian::Little);  // device size in bytes
    if (dev_size >= 1024 && ctx.offset + dev_size >= ctx.offset) out.size = dev_size;
    out.set_confidence(Confidence::Verified,
                       "NILFS2 superblock, CRC32 verified (block size " +
                           std::to_string(1u << (10 + log_bs)) + ")");
    return true;
}

// Minix: superblock at byte 1024. v1/v2 s_magic at +0x10, v3 s_magic at +0x18.
bool validate_minix(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t sb = ctx.offset + 1024;
    uint16_t m12 = u16le(r, sb + 0x10);
    uint16_t m3 = u16le(r, sb + 0x18);

    const char* ver = nullptr;
    if (m12 == 0x137F || m12 == 0x138F) {
        ver = "1";
    } else if (m12 == 0x2468 || m12 == 0x2478) {
        ver = "2";
    } else if (m3 == 0x4D5A) {
        ver = "3";
    } else {
        return false;
    }

    if (ver[0] == '3') {
        uint32_t ninodes = u32(r, sb + 0, Endian::Little);
        uint16_t imap = u16le(r, sb + 6);
        uint16_t zmap = u16le(r, sb + 8);
        uint16_t log_zone = u16le(r, sb + 0x0C);
        uint32_t zones = u32(r, sb + 0x14, Endian::Little);
        uint16_t bsize = u16le(r, sb + 0x1C);
        if (bsize != 1024 && bsize != 2048 && bsize != 4096) return false;
        if (ninodes == 0 || zones == 0) return false;
        if (imap == 0 || imap > 8192 || zmap == 0) return false;
        if (log_zone > 8) return false;
    } else {
        // v1/v2: s_state (@+0x12) is MINIX_VALID_FS(1) / MINIX_ERROR_FS(2) — the
        // key discriminator for the 2-byte magic against random data.
        uint16_t ninodes = u16le(r, sb + 0);
        uint16_t imap = u16le(r, sb + 4);
        uint16_t zmap = u16le(r, sb + 6);
        uint16_t fdz = u16le(r, sb + 8);
        uint16_t log_zone = u16le(r, sb + 0x0A);
        uint32_t maxsize = u32(r, sb + 0x0C, Endian::Little);
        uint16_t state = u16le(r, sb + 0x12);
        if (state != 1 && state != 2) return false;
        if (ninodes == 0 || imap == 0 || zmap == 0 || fdz == 0 || maxsize == 0) return false;
        if (imap > 2048 || zmap > 8192 || log_zone > 4) return false;
        if (fdz <= imap + zmap) return false;  // data zones follow the bitmap blocks
    }

    Finding& out = ctx.out;
    out.type = "minix";
    out.category = "filesystem";
    out.endian = Endian::Little;
    out.version = ver;
    out.set_confidence(Confidence::Consistent, std::string("Minix v") + ver + " filesystem");
    return true;
}

// ReiserFS: superblock at 8 KiB (3.5) or 64 KiB (3.6); s_magic[10] at SB+0x34.
// Strong ASCII magic — a blocksize sanity check is enough.
bool validate_reiserfs(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t sb = ctx.offset;  // magic_offset places ctx.offset at the SB start
    uint32_t block_count = u32(r, sb + 0, Endian::Little);
    uint16_t blocksize = u16le(r, sb + 0x2C);
    if (block_count == 0) return false;
    if (!is_pow2(blocksize) || blocksize < 512 || blocksize > 8192) return false;

    // Format from the magic string variant at +0x34.
    std::string fmt = "3.5";
    if (auto mb = r.bytes(sb + 0x34, 9)) {
        std::string m(reinterpret_cast<const char*>(mb->data()), 9);
        if (m.rfind("ReIsEr2Fs", 0) == 0) fmt = "3.6";
        else if (m.rfind("ReIsEr3Fs", 0) == 0) fmt = "3.6 (relocated journal)";
    }

    Finding& out = ctx.out;
    out.type = "reiserfs";
    out.category = "filesystem";
    out.endian = Endian::Little;
    out.size = static_cast<size_t>(block_count) * blocksize;
    out.version = fmt;
    out.set_confidence(Confidence::Consistent,
                       "ReiserFS " + fmt + " superblock (block size " + std::to_string(blocksize) + ")");
    return true;
}

// UFS/FFS: fs_magic (0x00011954 UFS1, 0x19540119 UFS2) at SB+0x55C, either endian.
bool validate_ufs(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t sb = ctx.offset;  // magic_offset places ctx.offset at the SB start
    const size_t moff = sb + 0x55C;

    Endian e;
    const char* ver;
    uint32_t le = u32(r, moff, Endian::Little);
    uint32_t be = u32(r, moff, Endian::Big);
    if (le == 0x00011954) { e = Endian::Little; ver = "UFS1"; }
    else if (le == 0x19540119) { e = Endian::Little; ver = "UFS2"; }
    else if (be == 0x00011954) { e = Endian::Big; ver = "UFS1"; }
    else if (be == 0x19540119) { e = Endian::Big; ver = "UFS2"; }
    else return false;

    uint32_t bsize = u32(r, sb + 0x30, e);  // fs_bsize
    uint32_t fsize = u32(r, sb + 0x34, e);  // fs_fsize
    if (!is_pow2(bsize) || bsize < 512 || bsize > 65536) return false;
    if (!is_pow2(fsize) || fsize < 512 || fsize > bsize) return false;

    Finding& out = ctx.out;
    out.type = "ufs";
    out.category = "filesystem";
    out.endian = e;
    out.version = ver;
    out.set_confidence(Confidence::Consistent,
                       std::string(ver) + " superblock (block size " + std::to_string(bsize) + ")");
    return true;
}

// APFS: nx_superblock at block 0; nx_magic "NXSB" at +0x20, block size at +0x24.
bool validate_apfs(ValidatorCtx& ctx) {
    const Reader& r = ctx.reader;
    const size_t sb = ctx.offset;  // container superblock start
    uint32_t block_size = u32(r, sb + 0x24, Endian::Little);
    uint64_t block_count = u64(r, sb + 0x28, Endian::Little);
    if (!is_pow2(block_size) || block_size < 512 || block_size > 65536) return false;
    if (block_count == 0) return false;

    Finding& out = ctx.out;
    out.type = "apfs";
    out.category = "filesystem";
    out.endian = Endian::Little;
    // Size to the whole container so the block-0 superblock owns its region and the
    // checkpoint-descriptor NXSB copies inside it are suppressed (one apfs finding).
    uint64_t total = block_size * block_count;
    if (total >= block_size && ctx.offset + total >= ctx.offset) out.size = total;
    out.set_confidence(Confidence::Consistent,
                       "APFS container superblock (block size " + std::to_string(block_size) + ")");
    return true;
}

// LogFS: the 64-bit magic 0x7a3a8e5cb9d5bf67 is essentially unique (an 8-byte
// match is strong evidence on its own). Deprecated FS, near-zero in IoT.
bool validate_logfs(ValidatorCtx& ctx) {
    Finding& out = ctx.out;
    out.type = "logfs";
    out.category = "filesystem";
    out.endian = Endian::Big;
    out.set_confidence(Confidence::Consistent, "LogFS superblock magic");
    return true;
}

}  // namespace ft

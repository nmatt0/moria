// mime.hpp — map a moria type name to a MIME type for the JSON output.
//
// Rationale: moria is built for LLM tool calling, where pipelines often key on
// MIME. `file --mime-type` returns application/octet-stream for nearly every
// firmware filesystem/container, which carries no information; moria emits a
// specific `application/x-<type>` instead. Where `file` DOES have a specific
// MIME (ELF, Intel HEX, ISO, PEM, Raspberry Pi EEPROM) we match its spelling
// so downstream consumers see one vocabulary. Registered IANA types
// (image/*, application/pdf, application/zip, application/gzip, ...) are used
// verbatim.
#pragma once

#include <string>

namespace ft {

// Returns a MIME type for a moria finding type. Unknown types fall back to
// application/octet-stream (an honest "opaque binary", as `file` does).
inline const char* mime_for_type(const std::string& t) {
    // --- registered IANA / de-facto standard types ------------------------
    if (t == "gzip") return "application/gzip";
    if (t == "xz") return "application/x-xz";
    if (t == "bzip2") return "application/x-bzip2";
    if (t == "zstd") return "application/zstd";
    if (t == "lz4" || t == "lz4_legacy") return "application/x-lz4";
    if (t == "zip") return "application/zip";
    if (t == "tar") return "application/x-tar";
    if (t == "cpio") return "application/x-cpio";
    if (t == "7z") return "application/x-7z-compressed";
    if (t == "rar") return "application/vnd.rar";
    if (t == "png") return "image/png";
    if (t == "jpeg") return "image/jpeg";
    if (t == "gif") return "image/gif";
    if (t == "bmp") return "image/bmp";
    if (t == "pdf") return "application/pdf";
    // --- match `file --mime-type`'s specific spellings --------------------
    if (t == "elf") return "application/x-executable";
    if (t == "upx") return "application/x-upx";
    if (t == "ihex") return "text/x-hex";
    if (t == "iso9660") return "application/x-iso9660-image";
    if (t == "certificate") return "application/x-x509-ca-cert";
    if (t == "verity") return "application/x-verity-hash";
    if (t == "private_key") return "application/x-pem-file";
    if (t == "rpi_eeprom") return "application/x-raspberry-eeprom";
    // --- filesystems (no registered MIME; specific x- form) ---------------
    if (t == "squashfs" || t == "squashfs_legacy") return "application/x-squashfs";
    if (t == "ext") return "application/x-ext";
    if (t == "f2fs") return "application/x-f2fs";
    if (t == "jffs2") return "application/x-jffs2";
    if (t == "ubi") return "application/x-ubi";
    if (t == "ubifs") return "application/x-ubifs";
    if (t == "yaffs2") return "application/x-yaffs2";
    if (t == "cramfs") return "application/x-cramfs";
    if (t == "erofs") return "application/x-erofs";
    if (t == "romfs") return "application/x-romfs";
    if (t == "btrfs") return "application/x-btrfs";
    if (t == "xfs") return "application/x-xfs";
    if (t == "hfsplus") return "application/x-hfsplus";
    if (t == "fat" || t == "fat32") return "application/x-fat";
    if (t == "exfat") return "application/x-exfat";
    if (t == "ntfs") return "application/x-ntfs";
    // --- containers / firmware / bootloaders ------------------------------
    if (t == "android_boot") return "application/x-android-bootimg";
    if (t == "android_sparse") return "application/x-android-sparse";
    if (t == "uimage") return "application/x-uimage";
    if (t == "fit") return "application/x-flat-image-tree";
    if (t == "dtb") return "application/x-dtb";
    if (t == "uboot") return "application/x-uboot";
    if (t == "uboot_env") return "application/x-uboot-env";
    if (t == "vbmeta") return "application/x-avb-vbmeta";
    if (t == "uefi_fv") return "application/x-uefi-firmware-volume";
    if (t == "lk") return "application/x-lk-bootloader";
    // --- partition tables -------------------------------------------------
    if (t == "gpt") return "application/x-gpt";
    if (t == "mbr") return "application/x-mbr";
    // --- encrypted volumes ------------------------------------------------
    if (t == "luks1" || t == "luks2") return "application/x-luks";
    return "application/octet-stream";
}

}  // namespace ft

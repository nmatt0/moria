#include "validators/registry.hpp"

#include "validators/android_boot.hpp"
#include "validators/cpio.hpp"
#include "validators/deobf.hpp"
#include "validators/dtb.hpp"
#include "validators/elf.hpp"
#include "validators/esp32_part.hpp"
#include "validators/esp32_nvs.hpp"
#include "validators/ihex.hpp"
#include "validators/jffs2.hpp"
#include "validators/jpeg.hpp"
#include "validators/legacy_fs.hpp"
#include "validators/littlefs.hpp"
#include "validators/luks.hpp"
#include "validators/partition.hpp"
#include "validators/rae_rfp.hpp"
#include "validators/spiffs.hpp"
#include "validators/squashfs.hpp"
#include "validators/tar.hpp"
#include "validators/uboot_env.hpp"
#include "validators/ubi.hpp"
#include "validators/uefi_fv.hpp"
#include "validators/uimage.hpp"
#include "validators/upx.hpp"
#include "validators/vbf.hpp"
#include "validators/vbmeta.hpp"
#include "validators/verity.hpp"
#include "validators/yaffs2.hpp"
#include "validators/zip.hpp"

namespace ft {

Validator find_validator(const std::string& name) {
    if (name == "android_boot") return validate_android_boot;
    if (name == "deobf") return validate_deobf;
    if (name == "squashfs") return validate_squashfs;
    if (name == "uimage") return validate_uimage;
    if (name == "elf") return validate_elf;
    if (name == "cpio") return validate_cpio;
    if (name == "dtb") return validate_dtb;
    if (name == "ihex") return validate_ihex;
    if (name == "yaffs2") return validate_yaffs2;
    if (name == "jffs2") return validate_jffs2;
    if (name == "tar") return validate_tar;
    if (name == "zip") return validate_zip;
    if (name == "jpeg") return validate_jpeg;
    if (name == "rae_rfp") return validate_rae_rfp;
    if (name == "vbf") return validate_vbf;
    if (name == "upx") return validate_upx;
    if (name == "verity") return validate_verity;
    if (name == "vbmeta") return validate_vbmeta;
    if (name == "uefi_fv") return validate_uefi_fv;
    if (name == "uboot_env") return validate_uboot_env;
    if (name == "ubi") return validate_ubi;
    if (name == "ubifs") return validate_ubifs;
    if (name == "gpt") return validate_gpt;
    if (name == "esp32_partition_table") return validate_esp32_partition_table;
    if (name == "esp32_nvs") return validate_esp32_nvs;
    if (name == "mbr") return validate_mbr;
    if (name == "luks") return validate_luks;
    if (name == "nilfs2") return validate_nilfs2;
    if (name == "minix") return validate_minix;
    if (name == "reiserfs") return validate_reiserfs;
    if (name == "ufs") return validate_ufs;
    if (name == "apfs") return validate_apfs;
    if (name == "logfs") return validate_logfs;
    if (name == "littlefs") return validate_littlefs;
    if (name == "spiffs") return validate_spiffs;
    return nullptr;
}

}  // namespace ft

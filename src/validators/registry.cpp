#include "validators/registry.hpp"

#include "validators/android_boot.hpp"
#include "validators/cpio.hpp"
#include "validators/deobf.hpp"
#include "validators/dtb.hpp"
#include "validators/elf.hpp"
#include "validators/ihex.hpp"
#include "validators/jffs2.hpp"
#include "validators/jpeg.hpp"
#include "validators/rae_rfp.hpp"
#include "validators/squashfs.hpp"
#include "validators/tar.hpp"
#include "validators/ubi.hpp"
#include "validators/uimage.hpp"
#include "validators/vbf.hpp"
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
    if (name == "ubi") return validate_ubi;
    if (name == "ubifs") return validate_ubifs;
    return nullptr;
}

}  // namespace ft

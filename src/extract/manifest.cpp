#include "extract/manifest.hpp"

#include <cstdio>

#include "deobfuscate/scheme.hpp"
#include "extract/android_boot.hpp"
#include "extract/android_sparse.hpp"
#include "extract/compressed.hpp"
#include "extract/descramble.hpp"
#include "extract/cpio.hpp"
#include "extract/cramfs.hpp"
#include "extract/erofs.hpp"
#include "extract/ext.hpp"
#include "extract/exfat.hpp"
#include "extract/hfsplus.hpp"
#include "extract/xfs.hpp"
#include "extract/btrfs.hpp"

#include "extract/zip.hpp"
#include "extract/f2fs.hpp"
#include "extract/fat.hpp"
#include "extract/iso9660.hpp"
#include "extract/jffs2.hpp"
#include "extract/ntfs.hpp"
#include "extract/rae_rfp.hpp"
#include "extract/squashfs.hpp"
#include "extract/romfs.hpp"
#include "extract/tar.hpp"
#include "extract/yaffs2.hpp"
#include "extract/ubifs.hpp"
#include "extract/littlefs.hpp"
#include "extract/uboot_env.hpp"
#include "extract/esp32_nvs.hpp"
#include "extract/uimage.hpp"
#include "extract/upx.hpp"
#include "extract/vbf.hpp"
#include "extract/vbmeta.hpp"
#include "extract/fit.hpp"

namespace ft {

Extractor find_extractor(const std::string& type) {
    if (is_scheme(type)) return extract_descramble;  // vendor-encrypted -> descramble + recurse
    if (type == "squashfs") return extract_squashfs;
    if (type == "cpio") return extract_cpio;
    if (type == "ext") return extract_ext;
    if (type == "jffs2") return extract_jffs2;
    if (type == "tar") return extract_tar;
    if (type == "romfs") return extract_romfs;
    if (type == "cramfs") return extract_cramfs;
    if (type == "erofs") return extract_erofs;
    if (type == "f2fs") return extract_f2fs;
    if (type == "android_sparse") return extract_android_sparse;
    if (type == "zip") return extract_zip;
    if (type == "android_boot") return extract_android_boot;
    if (type == "fat" || type == "vfat" || type == "fat32") return extract_fat;
    if (type == "exfat") return extract_exfat;
    if (type == "ntfs" || type == "ntfs_filesystem") return extract_ntfs;
    if (type == "iso9660" || type == "iso") return extract_iso9660;
    if (type == "uimage") return extract_uimage;
    if (type == "littlefs") return extract_littlefs;
    if (type == "uboot_env") return extract_uboot_env;
    if (type == "esp32_nvs") return extract_esp32_nvs;
    if (type == "rae_rfp") return extract_rae_rfp;
    if (type == "vbf") return extract_vbf;
    if (type == "vbmeta") return extract_vbmeta;
    if (type == "upx") return extract_upx;
    if (type == "fit") return extract_fit;
    if (type == "gzip" || type == "xz" || type == "zstd" || type == "lz4" || type == "lz4_legacy")
        return extract_compressed;
    if (type == "yaffs2") return extract_yaffs2;
    if (type == "ubifs" || type == "ubi") return extract_ubifs;
    if (type == "hfsplus" || type == "hfsx") return extract_hfsplus;
    if (type == "xfs") return extract_xfs;
    if (type == "btrfs") return extract_btrfs;
    return nullptr;
}

namespace {

void esc(std::string& out, const std::string& s) {
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: {
                unsigned char uc = static_cast<unsigned char>(c);
                if (uc < 0x20 || uc >= 0x80) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", uc);
                    out += buf;
                } else {
                    out += c;
                }
            }
        }
    }
}

}  // namespace

std::string manifest_to_json(const Manifest& m) {
    std::string o = "{\"source\":\"";
    esc(o, m.source);
    o += "\",\"extracted\":[";
    for (size_t i = 0; i < m.entries.size(); ++i) {
        const Extracted& e = m.entries[i];
        if (i) o += ",";
        o += "{\"offset\":" + std::to_string(e.offset);
        o += ",\"type\":\"";
        esc(o, e.type);
        o += "\",\"root\":\"";
        esc(o, e.root);
        o += "\",\"status\":\"";
        esc(o, e.status);
        o += "\",\"files\":" + std::to_string(e.files);
        o += ",\"dirs\":" + std::to_string(e.dirs);
        o += ",\"symlinks\":" + std::to_string(e.symlinks);
        o += ",\"bytes\":" + std::to_string(e.bytes);
        o += ",\"depth\":" + std::to_string(e.depth);
        if (!e.warnings.empty()) {
            o += ",\"warnings\":[";
            for (size_t j = 0; j < e.warnings.size(); ++j) {
                if (j) o += ",";
                o += "\"";
                esc(o, e.warnings[j]);
                o += "\"";
            }
            o += "]";
        }
        o += "}";
    }
    o += "]";
    if (m.capped) {
        o += ",\"capped\":true,\"cap_reason\":\"";
        esc(o, m.cap_reason);
        o += "\"";
    }
    o += "}";
    return o;
}

}  // namespace ft

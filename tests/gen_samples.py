#!/usr/bin/env python3
"""Synthetic, minimal, valid-enough samples for each supported format.

Every builder crafts just enough of a header (and, where the validator needs it,
correct CRCs/derived sizes) that moria identifies it. These are deterministic
fixtures for dev and regression testing, independent of the big external corpora.

`MANIFEST` pairs each sample with the expected finding type and minimum
confidence. Run standalone to drop the fixtures into tests/samples/ for
inspection; `tests/test_samples.py` uses the builders + MANIFEST directly.
"""
import os
import struct
import zlib

# confidence tiers (mirror finding.hpp)
MAGIC, STRUCTURAL, CONSISTENT, VERIFIED = 25, 60, 85, 99


def _buf(n):
    return bytearray(n)


def squashfs_v4_le():
    b = _buf(1024)
    b[0:4] = b"hsqs"
    struct.pack_into("<I", b, 4, 5)          # inodes
    struct.pack_into("<I", b, 12, 131072)    # block_size
    struct.pack_into("<H", b, 20, 1)         # compression = gzip
    struct.pack_into("<H", b, 22, 17)        # block_log (1<<17 == 131072)
    struct.pack_into("<H", b, 26, 1)         # no_ids
    struct.pack_into("<H", b, 28, 4)         # s_major
    struct.pack_into("<Q", b, 40, 1024)      # bytes_used
    struct.pack_into("<Q", b, 48, 768)       # id_table_start (>=96, <=bytes_used)
    return bytes(b)


def squashfs_shsq():
    # Vendor modified-magic squashfs (TP-Link/Broadcom "shsq") with an otherwise
    # standard LE v4 body. moria must still identify it as squashfs (the extractor
    # accepts the variant and auto-detects the real block codec).
    b = bytearray(squashfs_v4_le())
    b[0:4] = b"shsq"
    return bytes(b)


def squashfs_sqsh_be():
    # Genuine big-endian squashfs v4 ("sqsh"): every field big-endian. Identify
    # must detect endianness and still validate the v4 header.
    b = _buf(1024)
    b[0:4] = b"sqsh"
    struct.pack_into(">I", b, 4, 5)          # inodes
    struct.pack_into(">I", b, 12, 131072)    # block_size
    struct.pack_into(">H", b, 20, 1)         # compression
    struct.pack_into(">H", b, 22, 17)        # block_log (1<<17 == 131072)
    struct.pack_into(">H", b, 26, 1)         # no_ids
    struct.pack_into(">H", b, 28, 4)         # s_major
    struct.pack_into(">Q", b, 40, 1024)      # bytes_used
    struct.pack_into(">Q", b, 48, 768)       # id_table_start (>=96, <=bytes_used)
    return bytes(b)


def ext4():
    b = _buf(4096)
    struct.pack_into("<I", b, 1024 + 0, 8)   # s_inodes_count
    struct.pack_into("<I", b, 1024 + 4, 4)   # s_blocks_count_lo
    struct.pack_into("<I", b, 1024 + 24, 0)  # s_log_block_size (1024<<0 * 4 = 4096)
    struct.pack_into("<H", b, 0x438, 0xEF53) # s_magic
    return bytes(b)


def ext4_corrupt():
    # A real-looking ext4 superblock whose s_log_block_size is out of range
    # (block size = 1024 << 99 is absurd). The identity fields hold, so moria's
    # soft-constraint path surfaces it at `magic` tier ("field out of range")
    # instead of dropping it. Guards the soft_constraints engine feature.
    b = _buf(4096)
    struct.pack_into("<I", b, 1024 + 0, 8)    # s_inodes_count
    struct.pack_into("<I", b, 1024 + 4, 4)    # s_blocks_count_lo
    struct.pack_into("<I", b, 1024 + 20, 0)   # s_first_data_block (valid: 0)
    struct.pack_into("<I", b, 1024 + 24, 99)  # s_log_block_size (OOB)
    struct.pack_into("<H", b, 0x438, 0xEF53)  # s_magic
    return bytes(b)


def erofs():
    b = _buf(4096)
    struct.pack_into("<I", b, 1024, 0xE0F5E1E2)  # magic
    b[1024 + 12] = 12                            # blkszbits
    struct.pack_into("<I", b, 1060, 1)           # blocks (1<<12 == 4096)
    return bytes(b)


def iso9660():
    b = _buf(32768 + 8)
    b[32768] = 1                 # volume descriptor type: primary
    b[32769:32774] = b"CD001"    # standard identifier
    b[32774] = 1                 # version
    return bytes(b)


def exfat():
    b = _buf(512)
    b[3:11] = b"EXFAT   "                 # fs name @3
    struct.pack_into("<I", b, 80, 2048)   # fat_offset
    struct.pack_into("<I", b, 84, 128)    # fat_length
    struct.pack_into("<I", b, 88, 4096)   # cluster_heap_offset
    struct.pack_into("<I", b, 92, 8192)   # cluster_count
    return bytes(b)


def fat():
    b = _buf(512)
    struct.pack_into("<H", b, 11, 512)   # bytes per sector
    struct.pack_into("<H", b, 19, 4096)  # total_sec16
    b[54:59] = b"FAT16"                   # FS-type string @54
    return bytes(b)


def fat32():
    b = _buf(512)
    struct.pack_into("<H", b, 11, 512)     # bytes per sector
    struct.pack_into("<I", b, 32, 131072)  # total_sec32
    b[82:87] = b"FAT32"                     # FS-type string @82
    return bytes(b)


def f2fs():
    b = _buf(4096)
    struct.pack_into("<I", b, 1024 + 0, 0xF2F52010)  # magic
    struct.pack_into("<I", b, 1024 + 16, 12)         # log_blocksize (4096)
    struct.pack_into("<I", b, 1024 + 20, 9)          # log_blocks_per_seg (512)
    struct.pack_into("<I", b, 1024 + 48, 8)          # segment_count
    return bytes(b)


def btrfs():
    b = _buf(0x10000 + 4096)
    sb = 0x10000
    b[sb + 64:sb + 72] = b"_BHRfS_M"               # magic
    struct.pack_into("<Q", b, sb + 112, 0x4000000)  # total_bytes
    struct.pack_into("<I", b, sb + 144, 4096)       # sectorsize
    struct.pack_into("<I", b, sb + 148, 16384)      # nodesize
    return bytes(b)


def xfs():
    b = _buf(4096)
    b[0:4] = b"XFSB"                          # magic (big-endian)
    struct.pack_into(">I", b, 4, 4096)        # blocksize
    struct.pack_into(">Q", b, 8, 1024)        # dblocks
    struct.pack_into(">Q", b, 56, 128)        # rootino
    struct.pack_into(">I", b, 84, 256)        # agblocks
    struct.pack_into(">I", b, 88, 4)          # agcount
    struct.pack_into(">H", b, 100, 0xB4B5)    # versionnum (v5)
    struct.pack_into(">H", b, 104, 512)       # inodesize
    return bytes(b)


def hfsplus():
    b = _buf(4096)
    struct.pack_into(">H", b, 1024 + 0, 0x482B)  # signature 'H+' (big-endian)
    struct.pack_into(">H", b, 1024 + 2, 4)       # version 4
    struct.pack_into(">I", b, 1024 + 40, 4096)   # blockSize (power of two)
    struct.pack_into(">I", b, 1024 + 44, 1)      # totalBlocks
    return bytes(b)


def cramfs():
    b = _buf(512)
    struct.pack_into("<I", b, 0, 0x28CD3D45)   # magic
    struct.pack_into("<I", b, 4, 512)          # size
    b[16:32] = b"Compressed ROMFS"             # signature (our matched magic)
    return bytes(b)


def romfs():
    b = _buf(256)
    b[0:8] = b"-rom1fs-"
    struct.pack_into(">I", b, 8, 256)          # full_size (big-endian)
    return bytes(b)


_CRC_T = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if _c & 1 else (_c >> 1)
    _CRC_T.append(_c)


def _crc_raw(init, data):  # table crc, no final inversion
    crc = init
    for x in data:
        crc = _CRC_T[(crc ^ x) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def _jffs2_crc(data):
    return _crc_raw(0, data)          # JFFS2: init 0


def _ubi_crc(data):
    return _crc_raw(0xFFFFFFFF, data)  # UBI/UBIFS: init 0xFFFFFFFF


def jffs2():
    b = _buf(256)
    struct.pack_into("<H", b, 0, 0x1985)       # magic
    struct.pack_into("<H", b, 2, 0xE001)       # nodetype = dirent
    struct.pack_into("<I", b, 4, 64)           # totlen
    struct.pack_into("<I", b, 8, _jffs2_crc(bytes(b[:8])))  # hdr_crc over first 8 bytes
    return bytes(b)


def ubi():
    b = _buf(128)
    b[0:4] = b"UBI#"
    b[4] = 1                                          # version
    struct.pack_into(">I", b, 60, _ubi_crc(bytes(b[:60])))  # hdr_crc (BE) over first 60
    return bytes(b)


def ubifs():
    b = _buf(4096)                                    # a superblock node is ~4096 bytes
    struct.pack_into("<I", b, 0, 0x06101831)          # magic
    struct.pack_into("<I", b, 16, 4096)               # len (<= file size)
    b[20] = 0                                         # node_type (superblock)
    struct.pack_into("<I", b, 4, _ubi_crc(bytes(b[8:4096])))  # crc over node[8:len]
    return bytes(b)


def yaffs2_be():
    b = _buf(512)
    struct.pack_into(">I", b, 0, 3)      # type = directory (big-endian)
    struct.pack_into(">I", b, 4, 1)      # parent_object_id
    struct.pack_into("<H", b, 8, 0xFFFF)  # deprecated sum anchor (byte-order-agnostic)
    b[10:16] = b"rootfs"
    return bytes(b)


def dtb():
    b = _buf(128)
    struct.pack_into(">I", b, 0, 0xD00DFEED)   # magic
    struct.pack_into(">I", b, 4, 128)          # totalsize
    struct.pack_into(">I", b, 8, 64)           # off_dt_struct
    struct.pack_into(">I", b, 12, 100)         # off_dt_strings
    struct.pack_into(">I", b, 16, 40)          # off_mem_rsvmap
    struct.pack_into(">I", b, 20, 17)          # version
    struct.pack_into(">I", b, 24, 16)          # last_comp_version
    return bytes(b)


def uimage():
    name = b"test kernel".ljust(32, b"\0")
    body = struct.pack(">IIIIIBBBB", 0, 0, 16, 0, 0, 2, 5, 2, 1) + name  # time..name; os=2 arch=5(mips) type=2 comp=2
    hdr = struct.pack(">I", 0x27051956) + struct.pack(">I", 0) + body    # magic + hcrc(0) + rest
    crc = zlib.crc32(hdr) & 0xFFFFFFFF
    hdr = hdr[:4] + struct.pack(">I", crc) + hdr[8:]                     # patch hcrc
    return hdr + b"\0" * 16                                              # + 16 bytes payload (ih_size)


def gzip():
    return bytes([0x1F, 0x8B, 0x08, 0x00]) + struct.pack("<I", 0) + bytes([0x00, 0x03]) + b"\0" * 16


def xz():
    return bytes([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x04]) + b"\0" * 16


def lz4():
    return bytes([0x04, 0x22, 0x4D, 0x18, 0x40]) + b"\0" * 16  # FLG version bits = 01


def lz4_legacy():
    # Legacy frame: magic 0x184C2102 then u32-le first-block-size (must satisfy the
    # sig's 0 < size <= 8421520 bound). Identification only; a real round-trippable
    # legacy stream is exercised in test_extract.py (needs the lz4 codec).
    import struct
    body = b"\x00" * 32
    return b"\x02\x21\x4c\x18" + struct.pack("<I", len(body)) + body


def zstd():
    return bytes([0x28, 0xB5, 0x2F, 0xFD, 0x00]) + b"\0" * 16  # frame header descriptor, reserved bit 0


def cpio_newc():
    fields = ["00000000"] * 13
    fields[6] = "00000000"   # c_filesize
    fields[11] = "00000001"  # c_namesize (1)
    hdr = b"070701" + "".join(fields).encode()  # 6 + 104 = 110 bytes
    body = hdr + b"\0"        # name
    return body.ljust(112, b"\0")


def _elf(ei_class, ei_data, machine):
    b = _buf(64)
    b[0:4] = b"\x7fELF"
    b[4] = ei_class          # 1=32, 2=64
    b[5] = ei_data           # 1=LE, 2=BE
    b[6] = 1                 # version
    endian = "<" if ei_data == 1 else ">"
    struct.pack_into(endian + "H", b, 16, 2)        # e_type = EXEC
    struct.pack_into(endian + "H", b, 18, machine)  # e_machine
    return bytes(b)


def elf32_le():
    return _elf(1, 1, 40)    # ARM


def elf64_le():
    return _elf(2, 1, 183)   # AArch64


def android_boot():
    b = _buf(1024)
    b[0:8] = b"ANDROID!"
    struct.pack_into("<I", b, 8, 4096)   # kernel_size
    struct.pack_into("<I", b, 12, 512)   # ramdisk_size
    return bytes(b)


def android_sparse():
    return struct.pack("<IHHHHIII", 0xED26FF3A, 1, 0, 28, 12, 4096, 16, 0) + b"\0" * 16


def rpi_eeprom():
    b = _buf(512)
    struct.pack_into("<I", b, 0, 0x0FF0AA55)  # bytes 55 aa f0 0f
    struct.pack_into("<I", b, 4, 512)
    return bytes(b)


def yaffs2():
    b = _buf(512)
    struct.pack_into("<I", b, 0, 3)      # type = directory
    struct.pack_into("<I", b, 4, 1)      # parent_object_id
    struct.pack_into("<H", b, 8, 0xFFFF) # deprecated sum (our anchor)
    b[10:16] = b"rootfs"                 # name
    return bytes(b)


def ihex():
    data = bytes(range(16))
    rec = bytes([0x10, 0x00, 0x00, 0x00]) + data
    checksum = (-sum(rec)) & 0xFF
    line = ":" + rec.hex().upper() + f"{checksum:02X}" + "\r\n"
    line += ":00000001FF\r\n"  # EOF record
    return line.encode()


def png():
    ihdr = struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + ihdr + b"\0" * 8


def gif():
    return b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00" + b"\0" * 8


def bmp():
    b = _buf(54)
    b[0:2] = b"BM"
    struct.pack_into("<I", b, 2, 54)   # file_size
    return bytes(b)


def jpeg():
    # SOI + APP0/JFIF (len 16) + EOI, so the segment walk finds the end.
    return (bytes([0xFF, 0xD8, 0xFF, 0xE0]) + b"\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" +
            bytes([0xFF, 0xD9]))


def jpeg_fp_soi():
    # Regression: `ff d8 ff d8 ff d8 ...` (repeated SOI bytes, common in compressed
    # data) is NOT a JPEG. The 4th byte after the magic (0xD8) is not a valid
    # segment marker, so the signature constraint rejects it. Expected: no finding.
    return bytes([0xFF, 0xD8, 0xFF, 0xD8, 0xFF, 0xD8, 0x00, 0x50, 0x00, 0xF0]) + bytes(54)


def jpeg_fp_sof():
    # Regression: `ff d8 ff c0 ...` where the SOF0 "precision" byte is garbage
    # (0xAF, not 8 or 12). The marker passes the constraint but the frame-header
    # validation rejects it, so it is not reported as a JPEG. Expected: no finding.
    return (bytes([0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0xAF, 0x00, 0x08, 0x00, 0x08, 0x03]) +
            bytes(52))


def pdf():
    return b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< >>\nendobj\n"


def zip_():
    return b"PK\x03\x04" + struct.pack("<H", 20) + b"\0" * 24


def squashfs_v3_le():
    b = _buf(1024)
    b[0:4] = b"hsqs"
    struct.pack_into("<I", b, 4, 5)       # inodes
    struct.pack_into("<I", b, 8, 1024)    # bytes_used (u32, legacy layout)
    struct.pack_into("<H", b, 28, 3)      # s_major = 3
    return bytes(b)


def lk_image():
    b = _buf(64)
    struct.pack_into("<I", b, 0, 0x06882216)  # device header word
    b[8:12] = b"LK\x00\x00"                    # tag at offset 8
    return bytes(b)


def uboot():
    return b"\x00" * 64 + b"U-Boot 2019.07-rc1 (Aug 01 2019 - 12:00:00 +0000)\x00" + b"\xff" * 64


def pem_private_key():
    body = ("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt\n" * 6)
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + body +
            "-----END OPENSSH PRIVATE KEY-----\n").encode()


def pem_cert():
    body = ("MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\n" * 8)
    return ("-----BEGIN CERTIFICATE-----\n" + body + "-----END CERTIFICATE-----\n").encode()


def tar():
    # A real POSIX ustar member (empty file) + end-of-archive zero block. The
    # header checksum must be correct — the validator walks members and verifies it.
    h = bytearray(512)
    h[0:8] = b"file.txt"
    h[100:108] = b"0000644\x00"       # mode
    h[108:116] = b"0000000\x00"       # uid
    h[116:124] = b"0000000\x00"       # gid
    h[124:136] = b"00000000000\x00"   # size = 0 (octal, 12 bytes)
    h[136:148] = b"00000000000\x00"   # mtime
    h[148:156] = b" " * 8             # checksum field = spaces while summing
    h[156:157] = b"0"                 # typeflag: regular file
    h[257:263] = b"ustar\x00"
    h[263:265] = b"00"
    chksum = sum(h) & 0o777777
    h[148:156] = ("%06o\x00 " % chksum).encode()  # 6 octal digits, NUL, space
    return bytes(h) + bytes(512)       # + zero block terminates the archive


def sevenzip():
    return bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04]) + b"\0" * 24


def rar():
    return b"Rar!\x1a\x07\x00" + b"\xcf\x90\x73\x00\x00\x0d" + b"\0" * 16


def bzip2():
    return b"BZh9" + b"\x31\x41\x59\x26\x53\x59" + b"\0" * 16


def dlink_shrs():
    # SHRS header (magic + BE u32 enc_size @8 + IV @0x0C) with junk ciphertext:
    # identifies as dlink_shrs at structural tier (no working key -> not verified).
    import struct
    img = bytearray(0x6DC + 64)
    img[0:4] = b"SHRS"
    img[8:12] = struct.pack(">I", 64)          # enc_size
    img[0x0C:0x1C] = bytes(range(16))          # IV
    img[0x6DC:] = bytes((i * 7) & 0xFF for i in range(64))
    return bytes(img)


def dlink_encrpted_img():
    # "encrpted_img" magic + junk ciphertext -> dlink_encrpted_img at structural.
    return b"encrpted_img" + b"\x00\x00\x00\x00" + bytes((i * 5) & 0xFF for i in range(256))


def openssl_salted():
    # OpenSSL "Salted__" magic + salt + junk -> openssl_salted at structural.
    return b"Salted__" + bytes(range(8)) + bytes((i * 3) & 0xFF for i in range(128))


def dlink_mh01():
    # "MH01" header (0x41) + a Salted__ payload of junk -> dlink_mh01 structural.
    import struct
    h = bytearray(0x41)
    h[0:4] = b"MH01"
    h[0x18:0x1C] = struct.pack("<I", 0x60)      # enc_size
    h[32:64] = b"00112233445566778899aabbccddeeff"  # IV as ASCII-hex
    return bytes(h) + b"Salted__" + bytes(range(8)) + bytes((i * 9) & 0xFF for i in range(0x50))


def dlink_dlk():
    # Valid two-header DLK structure (sig_size=0, second DLK @0x50) with junk
    # ciphertext -> identifies at structural (no working key in the table).
    import struct
    h1 = bytearray(0x50)
    h1[0:3] = b"DLK"
    h1[0x2C:0x30] = struct.pack("<I", 0)
    h2 = bytearray(0x50)
    h2[0:3] = b"DLK"
    h2[0x10:0x14] = struct.pack("<I", 0x20)
    h2[0x2C:0x30] = struct.pack("<I", 0x40)
    return bytes(h1) + bytes(h2) + bytes((i * 11) & 0xFF for i in range(0x40))


def dlink_tlv():
    # Valid TLV structure: magic + model/board strings + Salted__ payload @0x74.
    t = bytearray(0x74)
    t[0:4] = bytes([0x64, 0x80, 0x19, 0x40])
    t[4:9] = b"MODEL"
    t[0x24:0x29] = b"BOARD"
    return bytes(t) + b"Salted__" + bytes(range(8)) + bytes(0x40)


def engenius():
    # EnGenius keyless XOR: pattern @0x5C, length @0x20 (BE), model_len @0x84 (BE);
    # payload from 136+model_len XORed with a fixed 8-byte key phase-anchored to
    # where it appears in the file (a plaintext zero-run reveals it). Decrypts to
    # a squashfs -> identifies engenius at verified tier.
    import struct
    key = bytes([0xAC, 0x78, 0x3C, 0x9E, 0xCF, 0x67, 0xB3, 0x59])
    ml = 4
    hdr_end = 136 + ml
    payload = b"hsqs" + bytes(60) + b"\x00" * 8 + bytes(60)  # magic + a zero-run @64
    ref = hdr_end + payload.find(b"\x00" * 8)
    length = hdr_end + len(payload)
    out = bytearray(length)
    out[0x20:0x24] = struct.pack(">I", length)
    out[0x5C:0x63] = bytes.fromhex("12345678") + b"all"
    out[0x84:0x88] = struct.pack(">I", ml)
    for i in range(len(payload)):
        a = hdr_end + i
        out[a] = payload[i] ^ key[(a - ref) % 8]
    return bytes(out)


def android_magic_at_zero():
    # Regression for the signature dedup: an "ANDROID!" magic at offset 0 with a
    # garbage (non-boot) header. The curated android_boot validator rejects it, and
    # the imported firmware DB's generic magic-only "android_bootimg" twin is
    # dropped at load time as a duplicate of that validated magic. So: no finding.
    return b"ANDROID!" + bytes((i * 7 + 3) & 0xFF for i in range(2040))


def lantronix():
    # Lantronix device-server ROM: "NUEVO-<digit>\0" header + payload.
    return b"NUEVO-2\x00" + bytes((i * 13 + 5) & 0xFF for i in range(1024))


def random_blob():
    # deterministic pseudo-random, no known magic
    return bytes((i * 37 + 11) & 0xFF for i in range(2048))


def text_file():
    return b"hostname=router\nadmin=1\n" * 20


def android_magic_string():
    # Regression: the "ANDROID!" magic also occurs as a bootloader string literal
    # (seen in a VStarcam CB73 U-Boot: "ANDROID!\0\0\0\0Prepare kernel parameters...").
    # Parsed as a boot header the fields are ASCII garbage (header_version huge,
    # declared size >> file). moria must reject it, not report a to-EOF android_boot
    # that swallows the real kernel/rootfs after it. Expected finding: none.
    # Magic sits mid-file (as in the real dump, not at offset 0) so this exercises
    # the scanning android_boot validator, not the offset-0-only generic signature.
    s = (b"ANDROID!\x00\x00\x00\x00Prepare kernel parameters ...\n\x00\x00"
         b"mem\x00mem boot start\n\x00mem boot error\n\x00")
    return bytes(64) + s + bytes(2048)


# name -> (builder, expected_type or None, min_confidence)
MANIFEST = [
    ("squashfs_v4_le.bin", squashfs_v4_le, "squashfs", CONSISTENT),
    ("squashfs_v3_le.bin", squashfs_v3_le, "squashfs_legacy", STRUCTURAL),
    ("squashfs_shsq.bin", squashfs_shsq, "squashfs", STRUCTURAL),
    ("squashfs_sqsh_be.bin", squashfs_sqsh_be, "squashfs", STRUCTURAL),
    ("ext4.bin", ext4, "ext", CONSISTENT),
    ("ext4_corrupt.bin", ext4_corrupt, "ext", MAGIC),  # soft-constraint downgrade
    ("erofs.bin", erofs, "erofs", CONSISTENT),
    ("f2fs.bin", f2fs, "f2fs", CONSISTENT),
    ("hfsplus.bin", hfsplus, "hfsplus", CONSISTENT),
    ("xfs.bin", xfs, "xfs", CONSISTENT),
    ("btrfs.bin", btrfs, "btrfs", CONSISTENT),
    ("iso9660.bin", iso9660, "iso9660", CONSISTENT),
    ("exfat.bin", exfat, "exfat", CONSISTENT),
    ("fat16.bin", fat, "fat", CONSISTENT),
    ("fat32.bin", fat32, "fat32", CONSISTENT),
    ("cramfs.bin", cramfs, "cramfs", CONSISTENT),
    ("romfs.bin", romfs, "romfs", CONSISTENT),
    ("jffs2.bin", jffs2, "jffs2", VERIFIED),
    ("ubi.bin", ubi, "ubi", VERIFIED),
    ("ubifs.bin", ubifs, "ubifs", VERIFIED),
    ("device.dtb", dtb, "dtb", CONSISTENT),
    ("kernel.uimage", uimage, "uimage", VERIFIED),
    ("blob.gz", gzip, "gzip", STRUCTURAL),
    ("blob.xz", xz, "xz", STRUCTURAL),
    ("blob.lz4", lz4, "lz4", STRUCTURAL),
    ("blob.lz4l", lz4_legacy, "lz4_legacy", STRUCTURAL),
    ("blob.zst", zstd, "zstd", STRUCTURAL),
    ("initramfs.cpio", cpio_newc, "cpio", CONSISTENT),
    ("archive.tar", tar, "tar", STRUCTURAL),
    ("archive.7z", sevenzip, "7z", STRUCTURAL),
    ("archive.rar", rar, "rar", STRUCTURAL),
    ("blob.bz2", bzip2, "bzip2", STRUCTURAL),
    ("prog32.elf", elf32_le, "elf", CONSISTENT),
    ("prog64.elf", elf64_le, "elf", CONSISTENT),
    ("boot.img", android_boot, "android_boot", STRUCTURAL),
    ("super.sparse", android_sparse, "android_sparse", CONSISTENT),
    ("pieeprom.bin", rpi_eeprom, "rpi_eeprom", STRUCTURAL),
    ("aboot.lk", lk_image, "lk", MAGIC),
    ("u-boot.bin", uboot, "uboot", MAGIC),
    ("rootfs.yaffs2", yaffs2, "yaffs2", STRUCTURAL),
    ("rootfs_be.yaffs2", yaffs2_be, "yaffs2", STRUCTURAL),
    ("firmware.hex", ihex, "ihex", CONSISTENT),
    ("image.png", png, "png", CONSISTENT),
    ("image.gif", gif, "gif", STRUCTURAL),
    ("image.bmp", bmp, "bmp", STRUCTURAL),
    ("image.jpg", jpeg, "jpeg", CONSISTENT),
    ("doc.pdf", pdf, "pdf", STRUCTURAL),
    ("archive.zip", zip_, "zip", STRUCTURAL),
    ("id_ed25519", pem_private_key, "private_key", CONSISTENT),
    ("server.crt", pem_cert, "certificate", CONSISTENT),
    ("fw.shrs", dlink_shrs, "dlink_shrs", STRUCTURAL),
    ("fw.encrpted_img", dlink_encrpted_img, "dlink_encrpted_img", STRUCTURAL),
    ("fw.salted", openssl_salted, "openssl_salted", STRUCTURAL),
    ("fw.mh01", dlink_mh01, "dlink_mh01", STRUCTURAL),
    ("fw.dlk", dlink_dlk, "dlink_dlk", STRUCTURAL),
    ("fw.tlv", dlink_tlv, "dlink_tlv", STRUCTURAL),
    ("fw.engenius", engenius, "engenius", STRUCTURAL),
    ("fw.lantronix", lantronix, "lantronix_firmware", STRUCTURAL),
    ("android_magic_string.bin", android_magic_string, None, 0),
    ("android_magic_at_zero.bin", android_magic_at_zero, None, 0),
    ("jpeg_fp_soi.bin", jpeg_fp_soi, None, 0),
    ("jpeg_fp_sof.bin", jpeg_fp_sof, None, 0),
    ("random.bin", random_blob, None, 0),
    ("config.txt", text_file, None, 0),
]


def write_all(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, builder, _t, _c in MANIFEST:
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(builder())
    return len(MANIFEST)


if __name__ == "__main__":
    import sys
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "samples")
    n = write_all(outdir)
    print(f"wrote {n} synthetic samples to {outdir}")

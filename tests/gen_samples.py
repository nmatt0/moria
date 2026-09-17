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


def uboot_env():
    # U-Boot single environment: u32 crc32(data) + data, where data is a
    # NUL-separated key=value list ending in an empty entry, padded to ENV_SIZE.
    size = 0x2000
    vars = [b"bootcmd=bootm 0x82000000", b"bootargs=console=ttyS0,115200",
            b"baudrate=115200", b"ethaddr=00:11:22:33:44:55", b"ipaddr=10.0.0.1"]
    data = b"\x00".join(vars) + b"\x00\x00"
    data = data.ljust(size - 4, b"\x00")[:size - 4]
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return struct.pack("<I", crc) + data


def vbmeta():
    # Minimal AVB vbmeta: the 256-byte AvbVBMetaImageHeader (big-endian), no
    # authentication/auxiliary blocks (unsigned/verification-off form). All
    # offsets zero -> the validator's within() checks pass -> consistent.
    hdr = struct.pack(
        ">4sIIQQIQQQQQQQQQQQII48s80s",
        b"AVB0", 1, 0,       # magic, avb_major, avb_minor
        0, 0,               # auth_block_size, aux_block_size
        0,                  # algorithm_type (NONE)
        0, 0, 0, 0,         # hash/signature offset+size
        0, 0, 0, 0,         # public_key + metadata offset+size
        0, 0,               # descriptors offset+size
        0,                  # rollback_index
        0, 0,               # flags, rollback_index_location
        b"avbtool 1.2.0", b"")
    assert len(hdr) == 256
    return hdr


def uefi_fv():
    # UEFI Firmware Volume header (EFI_FIRMWARE_VOLUME_HEADER), 72-byte header.
    # The 16-bit header checksum makes the sum of all header UINT16 words zero.
    hlen = 0x48
    fvlen = 0x1000
    hdr = bytearray(hlen)
    hdr[16:32] = bytes([0x78, 0xE5, 0x8C, 0x8C, 0x3D, 0x8A, 0x1C, 0x4F,
                        0x99, 0x35, 0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3])  # FFS2 GUID
    struct.pack_into("<Q", hdr, 32, fvlen)
    hdr[40:44] = b"_FVH"
    struct.pack_into("<I", hdr, 44, 0x000004FE)  # attributes
    struct.pack_into("<H", hdr, 48, hlen)        # header_length
    hdr[54] = 0
    hdr[55] = 2                                   # revision
    s = sum(struct.unpack_from("<%dH" % (hlen // 2), hdr))
    struct.pack_into("<H", hdr, 50, (-s) & 0xFFFF)  # checksum -> total sum 0
    return bytes(hdr) + b"\xff" * (fvlen - hlen)


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


def _upx_trailer(fmt=22, method=2, version=14, level=8, u_len=0xC00, c_len=0x400, filt=0):
    # A UPX PackHeader trailer (little-endian, non-DOS, 32 bytes). The final byte
    # is the header checksum UPX has embedded since version 10: sum of bytes
    # [4..30] modulo 251. moria verifies it, so a correct one -> verified tier.
    p = bytearray(32)
    p[0:4] = b"UPX!"
    p[4], p[5], p[6], p[7] = version, fmt, method, level
    struct.pack_into("<I", p, 16, u_len)
    struct.pack_into("<I", p, 20, c_len)
    struct.pack_into("<I", p, 24, u_len)   # u_file_size
    p[28] = filt
    p[31] = sum(p[4:31]) % 251
    return bytes(p)


def upx_packed():
    # A synthetic UPX-packed ELF64/amd64 stub: a section-stripped ELF header + one
    # PT_LOAD, a filler "compressed" body carrying the UPX loader ident banner,
    # then the checksum-verified PackHeader trailer as an overlay. No real UPX
    # payload is embedded (no third-party IP); only the public header structure is
    # synthesized. moria reports both elf (consistent) and upx (verified).
    ident = (b"$Info: This file is packed with the UPX executable packer "
             b"http://upx.sf.net $\n\x00"
             b"$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. "
             b"All Rights Reserved. $\n\x00")
    body_len = 0x400
    b = bytearray(body_len)
    b[0:4] = b"\x7fELF"
    b[4], b[5], b[6] = 2, 1, 1                # ELFCLASS64, ELFDATA2LSB, version
    struct.pack_into("<H", b, 16, 2)          # e_type = EXEC
    struct.pack_into("<H", b, 18, 62)         # e_machine = x86-64
    struct.pack_into("<I", b, 20, 1)
    struct.pack_into("<Q", b, 32, 64)         # e_phoff
    struct.pack_into("<Q", b, 40, 0)          # e_shoff = 0 (section table stripped)
    struct.pack_into("<H", b, 52, 64)         # e_ehsize
    struct.pack_into("<H", b, 54, 56)         # e_phentsize
    struct.pack_into("<H", b, 56, 1)          # e_phnum
    struct.pack_into("<H", b, 60, 0)          # e_shnum = 0
    struct.pack_into("<I", b, 64 + 0, 1)      # PT_LOAD
    struct.pack_into("<Q", b, 64 + 8, 0)      # p_offset
    struct.pack_into("<Q", b, 64 + 32, body_len)  # p_filesz (trailer is overlay)
    b[body_len - len(ident):body_len] = ident
    return bytes(b) + _upx_trailer(c_len=body_len, u_len=body_len * 3)


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


def verity():
    # dm-verity superblock (Linux verity_super_block), all little-endian. Fields
    # the validator reads: version==1, hash_type<=1, power-of-two data/hash block
    # sizes, data_blocks>0, sha256 algorithm. data_blocks=1 -> the hash tree is
    # just the superblock block, so the sized region fits this fixture.
    b = _buf(4096)
    b[0:8] = b"verity\x00\x00"
    struct.pack_into("<I", b, 8, 1)        # version
    struct.pack_into("<I", b, 12, 1)       # hash_type
    b[16:32] = bytes(range(16))            # uuid
    b[32:38] = b"sha256"                   # algorithm[32]
    struct.pack_into("<I", b, 64, 4096)    # data_block_size
    struct.pack_into("<I", b, 68, 4096)    # hash_block_size
    struct.pack_into("<Q", b, 72, 1)       # data_blocks
    struct.pack_into("<H", b, 80, 32)      # salt_size
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


def rae_rfp():
    # RAE Systems / Honeywell RFP firmware package: 0x29-byte header
    # ("RAE Systems Inc." + u16 version + u32 build_id + "RAE" + 16-byte digest)
    # then a section table of [u32 name_len; name; u32 flags; u32 usize; u32 csize;
    # data]. Two stored sections (IniFile, SIGN) landing exactly on EOF -> verified.
    def section(name, flags, data):
        return (struct.pack("<I", len(name)) + name +
                struct.pack("<III", flags, len(data), len(data)) + data)
    hdr = (b"RAE Systems Inc." + struct.pack("<H", 1) + struct.pack("<I", 0) +
           b"RAE" + bytes(16))
    ini = b"; minimal ini\r\n"
    return hdr + section(b"IniFile", 0, ini) + section(b"SIGN", 0, bytes(96))


def _crc16_ccitt(data):
    # CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF), the VBF per-block checksum.
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def vbf():
    # VBF (Versatile Binary Format) ECU container: ASCII "vbf_version = X.Y;" +
    # a brace-delimited header block, then binary blocks
    # [u32 be start][u32 be len][data][u16 be crc16-over-decompressed].
    # data_format_identifier = 0x00 (raw): the per-block CRC16 is verifiable
    # here, so a two-block image landing exactly on EOF -> verified.
    hdr = (b'vbf_version = 3.0;\r\n\r\n'
           b'header {\r\n'
           b'   description = { "synthetic VBF" };\r\n'
           b'   sw_part_number = "AA00-14D007-AA";\r\n'
           b'   sw_part_type = DATA;\r\n'
           b'   data_format_identifier = 0x00;\r\n'
           b'   ecu_address = 0x730;\r\n'
           b'   file_checksum = 0x00000000;\r\n'
           b'}')

    def block(addr, data):
        return struct.pack(">II", addr, len(data)) + data + struct.pack(">H", _crc16_ccitt(data))

    b0 = bytes((i * 7 + 3) & 0xFF for i in range(256))
    b1 = b"CALIBRATION\x00" * 4
    return hdr + block(0x00FD0000, b0) + block(0x10000400, b1)


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


def gpt_disk():
    """A minimal valid GPT: protective MBR + LBA1 header + a 4-entry array with two
    real partitions (EFI System, Linux filesystem). Both CRC32s are correct, so
    moria reaches the verified tier. No third-party data."""
    import struct
    import zlib
    SECT = 512
    disk_sectors = 100
    buf = bytearray(disk_sectors * SECT)
    # protective MBR at LBA0: one 0xEE entry spanning the disk + 0x55AA.
    struct.pack_into("<B", buf, 0x1BE + 4, 0xEE)                 # type = GPT protective
    struct.pack_into("<I", buf, 0x1BE + 8, 1)                    # start LBA
    struct.pack_into("<I", buf, 0x1BE + 12, disk_sectors - 1)   # size
    buf[0x1FE], buf[0x1FF] = 0x55, 0xAA
    # partition entry array at LBA2 (4 * 128 = 512 bytes).
    EFI = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
    LINUX = bytes.fromhex("af3dc60f838472478e793d69d8477de4")
    arr = bytearray(4 * 128)
    def put_entry(i, tguid, first, last, name):
        o = i * 128
        arr[o:o + 16] = tguid
        arr[o + 16:o + 32] = bytes(range(16))                   # unique guid (arbitrary)
        struct.pack_into("<Q", arr, o + 32, first)
        struct.pack_into("<Q", arr, o + 40, last)
        nm = name.encode("utf-16-le")[:72]
        arr[o + 56:o + 56 + len(nm)] = nm
    put_entry(0, EFI, 34, 40, "ESP")
    put_entry(1, LINUX, 41, 60, "rootfs")
    arr_crc = zlib.crc32(bytes(arr)) & 0xFFFFFFFF
    # GPT header at LBA1.
    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<I", hdr, 8, 0x00010000)                  # revision 1.0
    struct.pack_into("<I", hdr, 12, 92)                         # header size
    struct.pack_into("<Q", hdr, 24, 1)                          # my_lba
    struct.pack_into("<Q", hdr, 32, disk_sectors - 1)           # alternate_lba
    struct.pack_into("<Q", hdr, 40, 34)                         # first usable
    struct.pack_into("<Q", hdr, 48, disk_sectors - 34)         # last usable
    hdr[56:72] = bytes(range(16, 32))                           # disk guid
    struct.pack_into("<Q", hdr, 72, 2)                          # partition_entry_lba
    struct.pack_into("<I", hdr, 80, 4)                          # num entries
    struct.pack_into("<I", hdr, 84, 128)                        # entry size
    struct.pack_into("<I", hdr, 88, arr_crc)                    # array crc
    hcrc = zlib.crc32(bytes(hdr)) & 0xFFFFFFFF                  # crc field is 0 here
    struct.pack_into("<I", hdr, 16, hcrc)
    buf[SECT:SECT + 92] = hdr
    buf[2 * SECT:2 * SECT + len(arr)] = arr
    return bytes(buf)


def mbr_disk():
    """A minimal MBR/DOS table: three primary partitions (FAT32, Linux, Linux) with
    valid boot flags and in-disk LBA ranges -> consistent tier."""
    import struct
    SECT = 512
    disk_sectors = 400
    buf = bytearray(disk_sectors * SECT)
    def put(i, ptype, start, count):
        o = 0x1BE + i * 16
        buf[o] = 0x00                                            # boot flag
        buf[o + 4] = ptype
        struct.pack_into("<I", buf, o + 8, start)
        struct.pack_into("<I", buf, o + 12, count)
    put(0, 0x0C, 1, 40)     # FAT32 (LBA)
    put(1, 0x83, 41, 60)    # Linux
    put(2, 0x83, 101, 90)   # Linux
    buf[0x1FE], buf[0x1FF] = 0x55, 0xAA
    return bytes(buf)


def esp32_part_table():
    """A minimal ESP-IDF partition table at 0x8000: nvs + phy_init + factory app
    (all recognized type/subtypes, sector-aligned, non-overlapping) + MD5
    terminator entry -> consistent tier. The image tail is erased (0xFF) flash."""
    import hashlib
    buf = _buf(0x20000)
    for i in range(len(buf)):
        buf[i] = 0xFF
    entries = [
        (0x01, 0x02, 0x9000, 0x6000, "nvs"),
        (0x01, 0x01, 0xF000, 0x1000, "phy_init"),
        (0x00, 0x00, 0x10000, 0x10000, "factory"),
    ]
    raw = bytearray()
    for ptype, subtype, off, size, label in entries:
        e = bytearray(32)
        e[0:2] = b"\xaa\x50"
        e[2], e[3] = ptype, subtype
        struct.pack_into("<I", e, 4, off)
        struct.pack_into("<I", e, 8, size)
        e[12:12 + len(label)] = label.encode()
        raw += e
    md5_entry = b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(bytes(raw)).digest()
    buf[0x8000:0x8000 + len(raw)] = raw
    buf[0x8000 + len(raw):0x8000 + len(raw) + 32] = md5_entry
    return bytes(buf)


# --- ESP-IDF NVS fixture helpers (also used by test_esp32_nvs.py) -------------

def nvs_crc(data):
    """The NVS CRC variant: zlib crc32 seeded with 0xFFFFFFFF."""
    return zlib.crc32(data, 0xFFFFFFFF) & 0xFFFFFFFF


def nvs_entry(ns, etype, key, data8, span=1, chunk=0xFF):
    """One 32-byte entry header (data8 = the 8-byte data field)."""
    e = bytearray(32)
    e[0], e[1], e[2], e[3] = ns, etype, span, chunk
    kb = key.encode()[:15]
    e[8:8 + len(kb)] = kb
    e[24:32] = data8
    struct.pack_into("<I", e, 4, nvs_crc(bytes(e[0:4]) + bytes(e[8:32])))
    return bytes(e)


def nvs_int(ns, etype, key, value):
    """A fixed-size integer/float entry (value packed little-endian)."""
    size = etype & 0x0F
    data8 = int(value).to_bytes(size, "little", signed=bool(etype & 0x10))
    return nvs_entry(ns, etype, key, data8.ljust(8, b"\xff"))


def nvs_varlen(ns, etype, key, value, chunk=0xFF):
    """A string/blob entry chain: header entry + continuation entries."""
    span = 1 + (len(value) + 31) // 32
    data8 = struct.pack("<HHI", len(value), 0, nvs_crc(value))
    entries = [nvs_entry(ns, etype, key, data8, span=span, chunk=chunk)]
    cont = value + b"\xff" * ((span - 1) * 32 - len(value))
    for i in range(0, len(cont), 32):
        entries.append(cont[i:i + 32])
    return entries


def nvs_namespace(index, name):
    return nvs_entry(0, 0x01, name, bytes([index]) + b"\xff" * 7)


def nvs_blob_index(ns, key, size, chunk_count, chunk_start):
    data8 = struct.pack("<IBBH", size, chunk_count, chunk_start, 0)
    return nvs_entry(ns, 0x48, key, data8)


def nvs_page(seqno, entries, state=0xFFFFFFFE, version=0xFE):
    """One 4 KiB page: header + entry state bitmap + the given 32-byte entries."""
    page = bytearray(b"\xff" * 4096)
    struct.pack_into("<I", page, 0, state)
    struct.pack_into("<I", page, 4, seqno)
    page[8] = version
    struct.pack_into("<I", page, 28, nvs_crc(bytes(page[4:28])))
    for i in range(len(entries)):
        sh = 2 * (i % 4)
        page[32 + i // 4] = (page[32 + i // 4] & ~(0b11 << sh)) | (0b10 << sh)
    pos = 64
    for e in entries:
        assert len(e) == 32
        page[pos:pos + 32] = e
        pos += 32
    return bytes(page)


def esp32_nvs_part():
    """A one-page NVS partition: namespace "wifi" with a string, a credential-
    looking string, and an integer -> verified tier (header + entry CRCs)."""
    entries = [
        nvs_namespace(1, "wifi"),
        *nvs_varlen(1, 0x21, "ssid", b"moria-testnet\x00"),
        *nvs_varlen(1, 0x21, "password", b"Sup3rSecret!\x00"),
        nvs_int(1, 0x04, "channel", 6),
    ]
    return nvs_page(1, entries) + b"\xff" * 4096  # one valid + one erased page


def luks1_hdr():
    """A LUKS1 phdr (big-endian): aes-xts-plain64, sha256, 512-bit master key."""
    import struct
    b = bytearray(4096)
    b[0:6] = b"LUKS\xba\xbe"
    struct.pack_into(">H", b, 6, 1)                # version
    b[0x08:0x08 + 3] = b"aes"                      # cipher-name
    b[0x28:0x28 + 11] = b"xts-plain64"            # cipher-mode
    b[0x48:0x48 + 6] = b"sha256"                  # hash spec
    struct.pack_into(">I", b, 0x68, 4096)         # payload offset (sectors)
    struct.pack_into(">I", b, 0x6C, 64)           # master-key bytes (512-bit)
    uuid = b"12345678-1234-1234-1234-123456789abc"
    b[0xA8:0xA8 + len(uuid)] = uuid
    return bytes(b)


def luks2_hdr():
    """A LUKS2 binary header + JSON metadata (aes-xts-plain64, argon2id, 512-bit)."""
    import struct
    hdr_size = 16384
    b = bytearray(hdr_size)
    b[0:6] = b"LUKS\xba\xbe"
    struct.pack_into(">H", b, 6, 2)                # version
    struct.pack_into(">Q", b, 8, hdr_size)        # hdr_size
    b[0x48:0x48 + 6] = b"sha256"                  # checksum alg
    uuid = b"eb43f8ab-cc9b-4cc0-a469-df5a35bcae82"
    b[0xA8:0xA8 + len(uuid)] = uuid
    struct.pack_into(">Q", b, 0x100, 0)           # hdr_offset (0 = primary)
    js = (b'{"keyslots":{"0":{"type":"luks2","key_size":64,'
          b'"kdf":{"type":"argon2id","time":4,"memory":1048576}}},'
          b'"segments":{"0":{"type":"crypt","offset":"16777216",'
          b'"encryption":"aes-xts-plain64","sector_size":512}},'
          b'"digests":{"0":{"type":"pbkdf2"}}}')
    b[0x1000:0x1000 + len(js)] = js
    return bytes(b)


# name -> (builder, expected_type or None, min_confidence)
def _sb_image(total, sb_off, fields):
    """A zero image of `total` bytes with (offset, struct-format, value) tuples
    packed in (offsets relative to sb_off). Helper for the legacy-fs superblocks."""
    import struct
    b = bytearray(total)
    for off, fmt, val in fields:
        struct.pack_into(fmt, b, sb_off + off, val)
    return bytes(b)


def nilfs2_sb():
    # superblock at 1024; s_magic 0x3434 @ +6, with a correct s_sum CRC32
    # (crc32_le(s_crc_seed, sb[0..s_bytes] with s_sum zeroed)).
    import struct
    import zlib
    b = bytearray(_sb_image(4096, 1024, [
        (6, "<H", 0x3434),        # s_magic
        (8, "<H", 0x88),          # s_bytes (checksummed length)
        (0x0C, "<I", 0x12345678), # s_crc_seed
        (0x14, "<I", 0),          # s_log_block_size -> 1024
        (0x18, "<Q", 8),          # s_nsegments
        (0x20, "<Q", 4194304),    # s_dev_size
        (0x30, "<I", 2048),       # s_blocks_per_segment
    ]))
    seed, s_bytes = 0x12345678, 0x88
    region = bytearray(b[1024:1024 + s_bytes])
    region[0x10:0x14] = b"\x00\x00\x00\x00"  # zero s_sum for the CRC
    crc = (zlib.crc32(bytes(region), seed ^ 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF
    struct.pack_into("<I", b, 1024 + 0x10, crc)
    return bytes(b)


def minix_sb():
    # Minix v3 superblock at 1024: s_magic 0x4D5A @ +0x18.
    return _sb_image(4096, 1024, [
        (0x00, "<I", 64),       # s_ninodes (v3: u32)
        (6, "<H", 1),           # s_imap_blocks
        (8, "<H", 1),           # s_zmap_blocks
        (0x14, "<I", 4096),     # s_zones
        (0x18, "<H", 0x4D5A),   # s_magic (v3)
        (0x1C, "<H", 1024),     # s_blocksize
    ])


def reiserfs_sb():
    # ReiserFS 3.6 superblock placed at 8 KiB; s_magic "ReIsEr2Fs" @ SB+0x34.
    b = bytearray(_sb_image(0x2200, 0x2000, [
        (0x00, "<I", 1000),     # s_block_count
        (0x2C, "<H", 4096),     # s_blocksize
    ]))
    b[0x2000 + 0x34:0x2000 + 0x34 + 9] = b"ReIsEr2Fs"
    return bytes(b)


def ufs_sb():
    # UFS1 superblock at 0; fs_magic 0x00011954 (LE) @ +0x55C.
    return _sb_image(0x600, 0, [
        (0x30, "<I", 8192),        # fs_bsize
        (0x34, "<I", 1024),        # fs_fsize
        (0x55C, "<I", 0x00011954), # fs_magic (UFS1, little-endian)
    ])


def apfs_sb():
    # APFS container superblock at 0; nx_magic "NXSB" @ +0x20.
    b = bytearray(_sb_image(4096, 0, [
        (0x24, "<I", 4096),     # nx_block_size
        (0x28, "<Q", 100000),   # nx_block_count
    ]))
    b[0x20:0x24] = b"NXSB"
    return bytes(b)


def logfs_sb():
    # LogFS 64-bit magic (big-endian) at offset 0.
    import struct
    b = bytearray(4096)
    struct.pack_into(">Q", b, 0, 0x7A3A8E5CB9D5BF67)
    return bytes(b)


def littlefs_img():
    """A minimal valid LittleFS image: block 0 holds the superblock commit (rev +
    "littlefs" name tag + inline-struct geometry + CCRC). Enough for a verified
    identify. Tags are 32-bit big-endian and XOR-chained (seed 0xffffffff); the
    CCRC is crc32_raw(0xffffffff, region) == zlib.crc32(region) ^ 0xffffffff over
    [rev .. ccrc tag]."""
    bs, bcnt = 4096, 2
    img = bytearray(b"\xff" * (bs * bcnt))
    base = 0
    region = bytearray()
    struct.pack_into("<I", img, base, 1); region += struct.pack("<I", 1)   # rev = 1
    off = 4
    ptag = 0xFFFFFFFF

    def emit_tag(tag, data):
        nonlocal off, ptag, region
        stored = tag ^ ptag
        struct.pack_into(">I", img, base + off, stored)   # tags are big-endian
        region += struct.pack(">I", stored)
        img[base + off + 4:base + off + 4 + len(data)] = data
        region += data
        ptag = tag
        off += 4 + len(data)

    emit_tag((0x0FF << 20) | (0 << 10) | 8, b"littlefs")            # superblock name
    inl = struct.pack("<6I", 0x00020001, bs, bcnt, 0xFF, 0x7FFFFFFF, 0x3FE)
    emit_tag((0x201 << 20) | (0 << 10) | 24, inl)                   # inline geometry
    ccrc = (0x500 << 20) | (0x3FF << 10) | 4                        # CCRC tag, size 4
    stored = ccrc ^ ptag
    struct.pack_into(">I", img, base + off, stored); region += struct.pack(">I", stored)
    crc = zlib.crc32(bytes(region)) ^ 0xFFFFFFFF
    struct.pack_into("<I", img, base + off + 4, crc)
    return bytes(img)


MANIFEST = [
    ("gpt.bin", gpt_disk, "gpt", VERIFIED),
    ("mbr.bin", mbr_disk, "mbr", CONSISTENT),
    ("littlefs.bin", littlefs_img, "littlefs", VERIFIED),
    ("esp32_part.bin", esp32_part_table, "esp32_partition_table", CONSISTENT),
    ("esp32_nvs.bin", esp32_nvs_part, "esp32_nvs", VERIFIED),
    ("nilfs2.bin", nilfs2_sb, "nilfs2", VERIFIED),
    ("minix.bin", minix_sb, "minix", CONSISTENT),
    ("reiserfs.bin", reiserfs_sb, "reiserfs", CONSISTENT),
    ("ufs.bin", ufs_sb, "ufs", CONSISTENT),
    ("apfs.bin", apfs_sb, "apfs", CONSISTENT),
    ("logfs.bin", logfs_sb, "logfs", CONSISTENT),
    ("luks1.bin", luks1_hdr, "luks1", CONSISTENT),
    ("luks2.bin", luks2_hdr, "luks2", CONSISTENT),
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
    ("prog.upx", upx_packed, "upx", VERIFIED),
    ("boot.img", android_boot, "android_boot", STRUCTURAL),
    ("super.sparse", android_sparse, "android_sparse", CONSISTENT),
    ("pieeprom.bin", rpi_eeprom, "rpi_eeprom", STRUCTURAL),
    ("aboot.lk", lk_image, "lk", MAGIC),
    ("u-boot.bin", uboot, "uboot", MAGIC),
    ("uboot.env", uboot_env, "uboot_env", VERIFIED),
    ("vbmeta.img", vbmeta, "vbmeta", CONSISTENT),
    ("firmware.fv", uefi_fv, "uefi_fv", VERIFIED),
    ("rootfs.yaffs2", yaffs2, "yaffs2", STRUCTURAL),
    ("rootfs_be.yaffs2", yaffs2_be, "yaffs2", STRUCTURAL),
    ("hashtree.verity", verity, "verity", CONSISTENT),
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
    ("fw.rfp", rae_rfp, "rae_rfp", VERIFIED),
    ("fw.vbf", vbf, "vbf", VERIFIED),
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

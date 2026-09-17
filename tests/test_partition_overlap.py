#!/usr/bin/env python3
"""Regression for the partition-boundary overrun fix (PR #33).

A finding's self-declared size can overrun a region the partition table already
accounts for (a stale superblock in unpartitioned space still recording its
pre-repartition size). The scanner used to skip the whole extent, stepping over
the real partition's superblock so it was never validated and went missing. The
fix clamps the skip (and the resolve owner-skip) at partition boundaries.

Fully self-contained (hand-built GPT + synthetic ext superblocks, no mkfs tools).
It is a differential: with the GPT present the hidden partition is recovered;
with the GPT zeroed the same stale finding hides it — which proves the partition
table is what rescues it. Run: python3 tests/test_partition_overlap.py
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

SECT = 512


def ext_sb(buf, off, size_bytes, block_size=4096):
    """Plant a minimal ext superblock at image offset `off` (moria: ext consistent,
    finding size = s_blocks_count_lo * (1024 << s_log_block_size))."""
    log = block_size.bit_length() - 1 - 10          # 4096 -> 2
    blocks = size_bytes // block_size
    sb = off + 1024
    struct.pack_into("<I", buf, sb + 0, 1000)       # s_inodes_count
    struct.pack_into("<I", buf, sb + 4, blocks)     # s_blocks_count_lo
    struct.pack_into("<I", buf, sb + 20, 0)         # s_first_data_block
    struct.pack_into("<I", buf, sb + 24, log)       # s_log_block_size
    struct.pack_into("<H", buf, off + 0x438, 0xEF53)  # magic


def build_image(with_gpt=True):
    """A 2 MB image:
      GPT partitions rootfs@0x10000, userdata@0x40000 (member offsets).
      A STALE ext @0x8000 sized 256 KB -> extent 0x8000..0x48000, overrunning the
      real userdata partition start at 0x40000.
      A REAL ext (userdata) @0x40000 sized 256 KB -> extent 0x40000..0x80000, which
      extends beyond the stale extent (so it is not merely interior noise)."""
    disk_sectors = 4096                              # 2 MB
    buf = bytearray(disk_sectors * SECT)

    if with_gpt:
        # protective MBR
        struct.pack_into("<B", buf, 0x1BE + 4, 0xEE)
        struct.pack_into("<I", buf, 0x1BE + 8, 1)
        struct.pack_into("<I", buf, 0x1BE + 12, disk_sectors - 1)
        buf[0x1FE], buf[0x1FF] = 0x55, 0xAA
        LINUX = bytes.fromhex("af3dc60f838472478e793d69d8477de4")
        arr = bytearray(4 * 128)

        def put(i, first, last, name):
            o = i * 128
            arr[o:o + 16] = LINUX
            arr[o + 16:o + 32] = bytes(range(16))
            struct.pack_into("<Q", arr, o + 32, first)
            struct.pack_into("<Q", arr, o + 40, last)
            nm = name.encode("utf-16-le")[:72]
            arr[o + 56:o + 56 + len(nm)] = nm

        put(0, 0x10000 // SECT, 0x10000 // SECT + 100, "rootfs")
        put(1, 0x40000 // SECT, 0x80000 // SECT - 1, "userdata")
        arr_crc = zlib.crc32(bytes(arr)) & 0xFFFFFFFF
        hdr = bytearray(92)
        hdr[0:8] = b"EFI PART"
        struct.pack_into("<I", hdr, 8, 0x00010000)
        struct.pack_into("<I", hdr, 12, 92)
        struct.pack_into("<Q", hdr, 24, 1)
        struct.pack_into("<Q", hdr, 32, disk_sectors - 1)
        struct.pack_into("<Q", hdr, 40, 34)
        struct.pack_into("<Q", hdr, 48, disk_sectors - 34)
        hdr[56:72] = bytes(range(16, 32))
        struct.pack_into("<Q", hdr, 72, 2)
        struct.pack_into("<I", hdr, 80, 4)
        struct.pack_into("<I", hdr, 84, 128)
        struct.pack_into("<I", hdr, 88, arr_crc)
        struct.pack_into("<I", hdr, 16, zlib.crc32(bytes(hdr)) & 0xFFFFFFFF)
        buf[SECT:SECT + 92] = hdr
        buf[2 * SECT:2 * SECT + len(arr)] = arr

    ext_sb(buf, 0x8000, 256 * 1024)    # stale, overruns 0x40000
    ext_sb(buf, 0x40000, 256 * 1024)   # real userdata partition
    return bytes(buf)


def ext_offsets(data):
    with tempfile.NamedTemporaryFile(suffix=".img") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=60)
    doc = json.loads(r.stdout)
    return {x["offset"] for x in doc["findings"] if x["type"] == "ext"}


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    with_gpt = ext_offsets(build_image(with_gpt=True))
    no_gpt = ext_offsets(build_image(with_gpt=False))

    # The stale ext at 0x8000 is found in both cases.
    check(0x8000 in with_gpt, "stale ext @0x8000 should be found")
    # With the partition table, the real partition at 0x40000 is rescued from the
    # stale finding's overrun (the fix).
    check(0x40000 in with_gpt, "real partition ext @0x40000 hidden despite the GPT (regression!)")
    # Without any partition table, there is no boundary to rescue it: the stale
    # finding's skip hides 0x40000 (this is the pre-fix behavior, and confirms the
    # partition table is what makes the difference).
    check(0x40000 not in no_gpt,
          "control: without a GPT, 0x40000 should be hidden by the stale finding "
          "(the fixture no longer exercises the fix)")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: a partition table rescues a real partition from a stale finding's "
          "size overrun (PR #33)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""FAT12/16/32 identification: FS-type string must be confirmed by the BPB.

The FAT boot sector carries a human-readable FS-type label ("FAT12   ",
"FAT16   ", "FAT32   ") at offset 54 (82 for FAT32). That text also ships
verbatim inside firmware FAT-driver code and format tables -- for example a
VxWorks dosFsLib string table holds back-to-back "FAT12   " / "FAT16   " /
"MSystems" literals. Keying identification on the label alone (with only a
bytes-per-sector range check) false-claims those strings as filesystems: a
non-power-of-two bytes-per-sector such as 2601 still falls in 512..4096.

The identifier must confirm the mandatory BPB invariants the extractor also
enforces: bytes-per-sector and sectors-per-cluster are powers of two, and the
FAT count is non-zero.

Run: python3 tests/test_fat_id.py [path/to/moria]
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")


def moria_findings(data: bytes):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=120)
    return json.loads(r.stdout).get("findings", [])


def fat_findings(data: bytes):
    return [x for x in moria_findings(data) if x["type"] in ("fat", "fat32")]


def boot_sector(fstype, off, bytes_per_sec, sec_per_clus, num_fats, sec16=0, sec32=0):
    """A 512-byte FAT-ish boot sector with the given BPB fields and FS-type label."""
    b = bytearray(512)
    struct.pack_into("<H", b, 11, bytes_per_sec & 0xFFFF)
    b[13] = sec_per_clus & 0xFF
    b[16] = num_fats & 0xFF
    struct.pack_into("<H", b, 19, sec16 & 0xFFFF)
    struct.pack_into("<I", b, 32, sec32 & 0xFFFFFFFF)
    lbl = fstype.encode().ljust(8, b" ")[:8]
    b[off:off + 8] = lbl
    return bytes(b)


def vxworks_dosfs_strings():
    """The shape of the real VxWorks false positive: a run of dosFsLib format
    labels with no BPB around them. The byte at BPB offset 11 (bytes-per-sector)
    lands on arbitrary string data, here a non-power-of-two value in 512..4096."""
    b = bytearray(4096)
    blob = b"(none)\n\x00got bad symbol, %#x\n\x00\x00\x00\x00/\x00\x00\x00FAT12   \x00\x00\x00\x00FAT16   \x00\x00\x00\x00MSystems\x00"
    pos = 2048
    b[pos:pos + len(blob)] = blob
    f16 = b.index(b"FAT16")
    base = f16 - 54
    struct.pack_into("<H", b, base + 11, 2601)  # in 512..4096, not a power of two
    return bytes(b), base


def main():
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(("  PASS  " if cond else "  FAIL  ") + name)
        if not cond:
            fails += 1

    # --- True positives: a well-formed BPB is identified. ---
    tp16 = boot_sector("FAT16", 54, 512, 4, 2, sec16=4096)
    f = fat_findings(tp16)
    check("valid FAT16 boot sector identified", any(x["type"] == "fat" for x in f))

    tp32 = boot_sector("FAT32", 82, 512, 8, 2, sec32=131072)
    f = fat_findings(tp32)
    check("valid FAT32 boot sector identified", any(x["type"] == "fat32" for x in f))

    # Non-512 power-of-two sector size is still valid.
    tp16_4k = boot_sector("FAT16", 54, 4096, 1, 2, sec16=1024)
    check("valid FAT16 with 4096-byte sectors identified",
          any(x["type"] == "fat" for x in fat_findings(tp16_4k)))

    # --- False positives: the label alone, with a broken BPB, is rejected. ---
    data, _ = vxworks_dosfs_strings()
    check("VxWorks dosFsLib FAT12/FAT16 string table NOT identified as FAT",
          fat_findings(data) == [])

    # bytes-per-sector in range but not a power of two.
    fp_bps = boot_sector("FAT16", 54, 2601, 4, 2, sec16=4096)
    check("non-power-of-two bytes-per-sector (2601) rejected",
          fat_findings(fp_bps) == [])

    # sectors-per-cluster zero (the degenerate string-only match).
    fp_spc = boot_sector("FAT16", 54, 512, 0, 2, sec16=4096)
    check("zero sectors-per-cluster rejected", fat_findings(fp_spc) == [])

    # sectors-per-cluster not a power of two.
    fp_spc2 = boot_sector("FAT16", 54, 512, 3, 2, sec16=4096)
    check("non-power-of-two sectors-per-cluster (3) rejected",
          fat_findings(fp_spc2) == [])

    # zero FAT count.
    fp_nf = boot_sector("FAT16", 54, 512, 4, 0, sec16=4096)
    check("zero FAT count rejected", fat_findings(fp_nf) == [])

    # FAT32 variant of the same label-only false positive.
    fp32 = boot_sector("FAT32", 82, 2601, 8, 2, sec32=131072)
    check("non-power-of-two bytes-per-sector rejected (FAT32)",
          fat_findings(fp32) == [])

    print("-" * 60)
    if fails:
        print("FAIL: %d check(s) failed" % fails)
        return 1
    print("PASS: FAT identification confirms the BPB, not just the label")
    return 0


if __name__ == "__main__":
    sys.exit(main())

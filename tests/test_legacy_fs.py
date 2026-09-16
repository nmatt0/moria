#!/usr/bin/env python3
"""Legacy block-filesystem identify-only regression (issue #24).

NILFS2, Minix (v1/v2/v3), ReiserFS, UFS/FFS, APFS, LogFS — validated identify,
no extraction.

Layers:
  1. Synthetic, always-on: the hand-built superblocks from gen_samples, plus
     field-validation negatives for the weak-magic formats (NILFS2, Minix).
  2. Real mkfs.minix round-trip for v1/v2/v3 (self-skips if the tool is absent).

Run: python3 tests/test_legacy_fs.py
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")
sys.path.insert(0, HERE)
import gen_samples  # noqa: E402


def types_of(data: bytes):
    with tempfile.NamedTemporaryFile(suffix=".img") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=60)
    return json.loads(r.stdout)["findings"]


def has(findings, t):
    return [x for x in findings if x["type"] == t]


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # --- synthetic superblocks (each identified at its tier) ------------------
    # NILFS2 is CRC-verified; the rest are consistent (magic + field validation).
    for builder, t, tier in [(gen_samples.nilfs2_sb, "nilfs2", "verified"),
                             (gen_samples.minix_sb, "minix", "consistent"),
                             (gen_samples.reiserfs_sb, "reiserfs", "consistent"),
                             (gen_samples.ufs_sb, "ufs", "consistent"),
                             (gen_samples.apfs_sb, "apfs", "consistent"),
                             (gen_samples.logfs_sb, "logfs", "consistent")]:
        g = has(types_of(builder()), t)
        check(len(g) == 1 and g[0]["confidence_tier"] == tier,
              f"{t}: not identified at {tier} tier")

    # minix fixture is v3
    g = has(types_of(gen_samples.minix_sb()), "minix")
    check(g and g[0].get("version") == "3", "minix synthetic: version not 3")
    # ufs fixture is UFS1
    g = has(types_of(gen_samples.ufs_sb()), "ufs")
    check(g and g[0].get("version") == "UFS1", "ufs synthetic: not UFS1")

    # --- weak-magic false-positive guards -------------------------------------
    # NILFS2: magic present but zeroed geometry must be rejected.
    bad = bytearray(gen_samples.nilfs2_sb())
    struct.pack_into("<Q", bad, 1024 + 0x18, 0)   # s_nsegments = 0
    check(not has(types_of(bytes(bad)), "nilfs2"), "NILFS2: zero-geometry FP not rejected")

    # Minix: magic present but zero bitmap blocks must be rejected.
    bad = bytearray(gen_samples.minix_sb())
    struct.pack_into("<H", bad, 1024 + 6, 0)      # s_imap_blocks = 0
    check(not has(types_of(bytes(bad)), "minix"), "Minix: zero-bitmap FP not rejected")

    # A bare 0x3434 at the superblock offset with no valid fields is not NILFS2.
    junk = bytearray(4096)
    junk[1024 + 6:1024 + 8] = b"\x34\x34"
    check(not has(types_of(bytes(junk)), "nilfs2"), "NILFS2: bare 0x3434 magic FP not rejected")

    # --- real maker round-trips (each self-skips if its tool is absent) --------
    def mkfs_check(tool, argv, mb, fstype, want_tier, want_ver=None):
        if not shutil.which(tool):
            print(f"  ({tool} absent — real {fstype} round-trip skipped)")
            return
        with tempfile.TemporaryDirectory() as d:
            img = os.path.join(d, "fs.img")
            with open(img, "wb") as f:
                f.truncate(mb * 1024 * 1024)
            r = subprocess.run([tool] + argv + [img], capture_output=True)
            if r.returncode != 0:
                print(f"  ({tool} failed — {fstype} skipped: "
                      f"{r.stderr.decode(errors='replace').strip()[:70]})")
                return
            with open(img, "rb") as f:
                g = has(types_of(f.read()), fstype)
            check(len(g) == 1, f"real {fstype}: expected exactly one finding (got {len(g)})")
            if g:
                check(g[0]["confidence_tier"] == want_tier,
                      f"real {fstype}: tier {g[0]['confidence_tier']} != {want_tier}")
                if want_ver is not None:
                    check(want_ver in (g[0].get("version") or ""), f"real {fstype}: version wrong")

    for v in ("1", "2", "3"):
        mkfs_check("mkfs.minix", ["-" + v], 4, "minix", "consistent", v)
    mkfs_check("mkreiserfs", ["-f", "-q"], 40, "reiserfs", "consistent")
    mkfs_check("mkapfs", [], 16, "apfs", "consistent")
    mkfs_check("mkfs.nilfs2", ["-b", "1024", "-B", "256"], 16, "nilfs2", "verified")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: NILFS2/Minix/ReiserFS/UFS/APFS/LogFS identify (synthetic + FP guards + real Minix)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

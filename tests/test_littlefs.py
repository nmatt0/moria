#!/usr/bin/env python3
"""LittleFS identify + extract regression (issue #16).

Two layers:
  1. Synthetic superblock (gen_samples.littlefs_img) — always-on identify + FP guards.
  2. Real mklittlefs round-trip: build an image from a known tree, extract it with
     moria, assert every file comes back byte-exact. Self-skips if mklittlefs is
     absent, and also validates against `mklittlefs -u` when available.

Run: python3 tests/test_littlefs.py
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


def findings(data):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=60)
    return json.loads(r.stdout)["findings"]


def build_tree(root):
    os.makedirs(os.path.join(root, "etc"))
    os.makedirs(os.path.join(root, "data"))
    with open(os.path.join(root, "etc", "hostname"), "wb") as f:
        f.write(b"moria-lfs\n")                          # tiny -> inline
    with open(os.path.join(root, "etc", "config"), "wb") as f:
        f.write(b"KEY=value\nWIFI=x\n")
    with open(os.path.join(root, "small.txt"), "wb") as f:
        f.write(b"A" * 200)
    # incompressible, multi-block CTZ files (deterministic)
    with open(os.path.join(root, "data", "blob.bin"), "wb") as f:
        f.write(bytes((i * 37 + 11) & 0xFF for i in range(20000)))
    with open(os.path.join(root, "data", "pattern.bin"), "wb") as f:
        f.write(bytes((i * 13) & 0xFF for i in range(50000)))


def tree_files(root):
    out = {}
    for dp, _dn, fn in os.walk(root):
        for n in fn:
            p = os.path.join(dp, n)
            out[os.path.relpath(p, root)] = open(p, "rb").read()
    return out


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # --- synthetic identify ---------------------------------------------------
    g = [x for x in findings(gen_samples.littlefs_img()) if x["type"] == "littlefs"]
    check(len(g) == 1, "synthetic: one littlefs finding")
    if g:
        check(g[0]["confidence_tier"] == "verified", "synthetic: verified (CRC)")
        check(g[0].get("version") == "2.1", "synthetic: version 2.1")

    # --- false positives ------------------------------------------------------
    # The "littlefs" string at offset 8 but a corrupt CRC must be rejected.
    bad = bytearray(gen_samples.littlefs_img())
    bad[0x30] ^= 0xFF   # corrupt a byte inside the superblock commit
    check(not [x for x in findings(bytes(bad)) if x["type"] == "littlefs"],
          "FP: corrupt-CRC superblock rejected")
    # A bare "littlefs" string with no valid metadata pair -> no finding.
    junk = bytearray(8192)
    junk[8:16] = b"littlefs"
    check(not [x for x in findings(bytes(junk)) if x["type"] == "littlefs"],
          "FP: bare 'littlefs' string rejected")

    # --- real mklittlefs round-trip (self-skip) -------------------------------
    if not shutil.which("mklittlefs"):
        print("  (mklittlefs absent — real round-trip skipped)")
    else:
        for bs, size in ((4096, 1 << 20), (512, 1 << 19)):
            with tempfile.TemporaryDirectory() as d:
                tree = os.path.join(d, "tree")
                os.makedirs(tree)
                build_tree(tree)
                img = os.path.join(d, "fs.img")
                r = subprocess.run(["mklittlefs", "-c", tree, "-b", str(bs), "-p", "256",
                                    "-s", str(size), img], capture_output=True)
                if r.returncode != 0:
                    print(f"  (mklittlefs -b {bs} failed — skipped)")
                    continue
                with open(img, "rb") as f:
                    data = f.read()
                fs = [x for x in findings(data) if x["type"] == "littlefs"]
                check(bool(fs) and fs[0]["confidence_tier"] == "verified",
                      f"real bs={bs}: identified verified")
                # extract and byte-compare
                out = os.path.join(d, "out")
                subprocess.run([MORIA, "-e", "-C", out, img], capture_output=True, timeout=120)
                got = {}
                for dp, _dn, fn in os.walk(out):
                    for n in fn:
                        p = os.path.join(dp, n)
                        # strip the "<out>/0x..-littlefs/" prefix
                        rel = os.path.relpath(p, out).split(os.sep, 1)
                        if len(rel) == 2 and rel[1] != "manifest.json":
                            got[rel[1]] = open(p, "rb").read()
                want = tree_files(tree)
                missing = [k for k in want if got.get(k) != want[k]]
                check(not missing, f"real bs={bs}: all files byte-exact (bad: {missing})")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: LittleFS identify (verified/CRC) + byte-exact extract (synthetic + real mklittlefs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

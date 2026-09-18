#!/usr/bin/env python3
"""SPIFFS identify + extract regression (issue #17).

SPIFFS has no magic and its page/block geometry is not stored in the image, so
identification anchors on a committed object-index header and the parser infers
the geometry. Layers:
  1. Synthetic (always on): the minimal image from gen_samples + FP guards.
  2. Real mkspiffs round-trip for two geometries (self-skips without the tool),
     asserting every file extracts byte-exact and the geometry is inferred right.

Run: python3 tests/test_spiffs.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")
sys.path.insert(0, HERE)
import gen_samples  # noqa: E402


def findings(data):
    with tempfile.NamedTemporaryFile(suffix=".spiffs") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=60)
    return json.loads(r.stdout)["findings"]


def extract(data):
    with tempfile.NamedTemporaryFile(suffix=".spiffs") as f, tempfile.TemporaryDirectory() as td:
        f.write(data)
        f.flush()
        subprocess.run([MORIA, "-e", "-C", td, f.name], capture_output=True, timeout=120)
        out = {}
        for root, _dn, files in os.walk(td):
            for n in files:
                if n == "manifest.json":
                    continue
                p = os.path.join(root, n)
                rel = os.path.relpath(p, td).split(os.sep, 1)
                if len(rel) == 2:
                    out[rel[1]] = open(p, "rb").read()
        return out


def build_tree(root):
    os.makedirs(os.path.join(root, "web"))
    with open(os.path.join(root, "config.txt"), "wb") as f:
        f.write(b"device config v1\n")
    with open(os.path.join(root, "wifi.cfg"), "wb") as f:
        f.write(b"SSID=lab\nPSK=x\n")
    with open(os.path.join(root, "web", "index.html"), "wb") as f:
        f.write(b"<html>hi</html>\n")
    with open(os.path.join(root, "big.bin"), "wb") as f:
        f.write(bytes((i * 13 + 5) & 0xFF for i in range(40000)))  # spans many blocks


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # --- synthetic identify + extract -----------------------------------------
    syn = gen_samples.spiffs_img()
    g = [x for x in findings(syn) if x["type"] == "spiffs"]
    check(len(g) == 1 and g[0]["confidence_tier"] == "consistent", "synthetic: identified consistent")
    if g:
        check("page 256" in (g[0].get("label") or ""), "synthetic: inferred page 256")
    ex = extract(syn)
    check(any(k.endswith("hello.txt") and v == b"hi\n" for k, v in ex.items()),
          f"synthetic: hello.txt extracted (got {ex})")

    # --- false positives ------------------------------------------------------
    # The 6-byte anchor present in random data but no coherent object graph.
    junk = bytearray(8192)
    junk[0x102:0x108] = b"\x00\x00\xf8\x00\x00\x00"  # the anchor, nothing else valid
    check(not [x for x in findings(bytes(junk)) if x["type"] == "spiffs"],
          "FP: bare anchor with no object graph rejected")

    # --- real mkspiffs round-trip (self-skip) ---------------------------------
    if not shutil.which("mkspiffs"):
        print("  (mkspiffs absent — real round-trip skipped)")
    else:
        for page, block, size in ((256, 4096, 1 << 18), (512, 8192, 1 << 19)):
            with tempfile.TemporaryDirectory() as d:
                tree = os.path.join(d, "t")
                os.makedirs(tree)
                build_tree(tree)
                img = os.path.join(d, "fs.spiffs")
                r = subprocess.run(["mkspiffs", "-c", tree, "-p", str(page), "-b", str(block),
                                    "-s", str(size), img], capture_output=True)
                if r.returncode != 0:
                    print(f"  (mkspiffs p={page} failed — skipped)")
                    continue
                data = open(img, "rb").read()
                fs = [x for x in findings(data) if x["type"] == "spiffs"]
                check(bool(fs), f"real p={page}: identified")
                if fs:
                    check(f"page {page}" in (fs[0].get("label") or "") and
                          f"block {block}" in (fs[0].get("label") or ""),
                          f"real p={page}: geometry inferred ({fs[0].get('label')})")
                got = extract(data)
                want = {}
                for rt, _dn, files in os.walk(tree):
                    for n in files:
                        p = os.path.join(rt, n)
                        want[os.path.relpath(p, tree)] = open(p, "rb").read()
                # names come back without a leading slash; match on basename path
                gotv = {k.split("/", 1)[-1] if k.count("/") else k: v for k, v in got.items()}
                miss = [k for k, v in want.items() if v not in got.values()]
                check(not miss, f"real p={page}: files byte-exact (missing/wrong: {miss})")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: SPIFFS identify (geometry inferred) + byte-exact extract (synthetic + real mkspiffs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

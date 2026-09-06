#!/usr/bin/env python3
"""Carve-mode (`-c`) regression. Carve dumps each finding's raw byte range (and
the unidentified gaps) to disk WITHOUT parsing, so the one guarantee that must
hold is fidelity: every carved blob is byte-identical to that range of the input.

Self-contained (no external tools): builds a synthetic image out of gzip streams
and padding, carves it, and checks each blob against the source bytes plus the
CLI contract (default vs -A gap carving, dir refusal, -e/-c coexistence).

Run: python3 tests/test_carve.py
"""
import gzip
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

fails = 0


def check(cond, msg):
    global fails
    status = "PASS" if cond else "FAIL"
    print(f"  {status}  {msg}")
    if not cond:
        fails += 1


def build_image(path):
    """A header gap, two gzip streams, interior padding, and a trailing gap."""
    parts = []
    parts.append(b"\xde\xad\xbe\xef" * 512)          # 2 KiB non-gzip header (a gap)
    parts.append(gzip.compress(b"first payload\n" * 64))
    parts.append(b"\x00" * 4096)                     # interior padding
    parts.append(gzip.compress(bytes(range(256)) * 32))
    parts.append(b"\x11\x22\x33" * 100)              # 300 B trailing gap
    blob = b"".join(parts)
    with open(path, "wb") as f:
        f.write(blob)
    return blob


def run(args):
    return subprocess.run([MORIA, *args], capture_output=True, text=True)


def main():
    if not os.path.exists(MORIA):
        print("moria binary not built; run cmake --build build")
        return 1
    print("test_carve: carve-mode fidelity + CLI contract")

    with tempfile.TemporaryDirectory() as td:
        img = os.path.join(td, "img.bin")
        blob = build_image(img)

        # --- default carve ---
        r = run(["-c", img])
        check(r.returncode == 0, "carve exits 0")
        cdir = img + ".carved"
        check(os.path.isdir(cdir), "creates <file>.carved/")
        man_path = os.path.join(cdir, "manifest.json")
        check(os.path.exists(man_path), "writes manifest.json")

        man = json.load(open(man_path))
        check(man["source"] == img, "manifest source is the input path")
        check(len(man["carved"]) >= 2, "carves at least the 2 gzip findings")

        # THE guarantee: every carved blob == the source's byte range.
        fidelity = True
        for e in man["carved"]:
            data = open(os.path.join(cdir, e["file"]), "rb").read()
            if len(data) != e["size"] or data != blob[e["offset"]:e["offset"] + e["size"]]:
                fidelity = False
                print(f"      mismatch: {e['file']} off={e['offset']} size={e['size']}")
        check(fidelity, "every carved blob is byte-identical to its input range")

        # A gzip finding must be among what got carved.
        check(any(e["type"] == "gzip" for e in man["carved"]), "gzip findings carved by type name")

        # --- -A carves >= default (it also dumps sub-KiB gaps) ---
        ra = run(["-A", "-c", img])
        check(ra.returncode == 0, "-A carve exits 0")
        man_a = json.load(open(man_path))  # -A overwrote the same dir
        check(len(man_a["carved"]) >= len(man["carved"]), "-A carves at least as many regions")
        check(any(e["type"] == "unknown" for e in man_a["carved"]),
              "-A carves the sub-KiB header gap as unknown")

        # --- carve refuses a directory ---
        rd = run(["-c", td])
        check(rd.returncode == 2 and "directory" in rd.stderr, "carve of a directory errors (exit 2)")

        # --- -e and -c coexist without clobbering each other ---
        rec = run(["-e", "-c", img])
        check(rec.returncode == 0, "-e -c exits 0")
        check(os.path.isdir(img + ".extracted") and os.path.isdir(img + ".carved"),
              "-e -c produce sibling .extracted / .carved dirs")

    print("PASS" if fails == 0 else f"FAIL ({fails})")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

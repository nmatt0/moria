#!/usr/bin/env python3
"""MediaTek LK (Little Kernel) bootloader identify regression.

Synthesizes the 512-byte LK header (u32 magic 0x58881688, u32 payload size,
char name[32], u32 loadaddr, u32 mode) plus a payload, and checks moria's
identification: a well-formed image is `mtk_lk` at offset 0, consistent tier,
with the partition name as the label and size == header + payload. Negatives:
a wrong magic is silent; a valid magic over a non-printable name is rejected
(false-positive gate); a declared payload past EOF stays below consistent.
Self-contained; no external tools. Exit nonzero on any failure.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")

LK_MAGIC = 0x58881688


def lk_header(size, name=b"lk", magic=LK_MAGIC, loadaddr=0x41E00000, mode=0):
    hdr = struct.pack("<II", magic, size) + name[:32].ljust(32, b"\x00") + \
        struct.pack("<II", loadaddr, mode)
    return hdr.ljust(512, b"\x00")


def lk_image(payload, **kw):
    return lk_header(len(payload), **kw) + payload


def run_json(path):
    out = subprocess.run([MORIA, "-j", path], capture_output=True, text=True).stdout
    return json.loads(out)


def main():
    fails = []

    def check(cond, msg):
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            fails.append(msg)

    with tempfile.TemporaryDirectory() as td:
        # 1. Well-formed LK image: magic + 4 KiB payload, name "lk".
        payload = bytes((i * 7) & 0xFF for i in range(4096))
        img = os.path.join(td, "lk.img")
        with open(img, "wb") as f:
            f.write(lk_image(payload, name=b"lk"))
        lk = [f for f in run_json(img).get("findings", []) if f.get("type") == "mtk_lk"]
        check(len(lk) == 1, "one mtk_lk finding")
        if lk:
            check(lk[0]["offset"] == 0, "offset 0")
            check(lk[0]["size"] == 512 + len(payload), "size == header + payload")
            check(lk[0]["confidence_tier"] == "consistent", "consistent tier (payload fits)")
            check(lk[0].get("label") == "lk", "partition name parsed as label")

        # 2. Uppercase name variant ("LK"), as shipped by some vendors.
        img2 = os.path.join(td, "lk_upper.bin")
        with open(img2, "wb") as f:
            f.write(lk_image(payload, name=b"LK"))
        lk = [f for f in run_json(img2).get("findings", []) if f.get("type") == "mtk_lk"]
        check(len(lk) == 1 and lk[0].get("label") == "LK", "uppercase 'LK' name identified")

        # 3. Embedded at a nonzero offset inside a flash dump.
        emb = os.path.join(td, "emb.bin")
        with open(emb, "wb") as f:
            f.write(b"\xff" * 0x10000 + lk_image(payload) + os.urandom(0x200))
        lk = [f for f in run_json(emb).get("findings", []) if f.get("type") == "mtk_lk"]
        check(len(lk) == 1 and lk[0]["offset"] == 0x10000, "embedded mtk_lk @0x10000")

        # 4. FP guard: correct magic but a non-printable name -> rejected.
        bad = os.path.join(td, "bad_name.bin")
        with open(bad, "wb") as f:
            f.write(lk_image(payload, name=bytes([1, 2, 3, 4, 5, 6])))
        lk = [f for f in run_json(bad).get("findings", []) if f.get("type") == "mtk_lk"]
        check(len(lk) == 0, "fp: magic + non-printable name rejected")

        # 5. FP guard: wrong magic entirely -> no mtk_lk.
        wrong = os.path.join(td, "wrong_magic.bin")
        with open(wrong, "wb") as f:
            f.write(lk_image(payload, magic=0x12345678))
        lk = [f for f in run_json(wrong).get("findings", []) if f.get("type") == "mtk_lk"]
        check(len(lk) == 0, "fp: wrong magic not identified as mtk_lk")

        # 6. Declared payload far past EOF: valid header, but the span does not
        #    fit, so it must stay below the consistent tier (not claim a bogus size).
        trunc = os.path.join(td, "trunc.bin")
        with open(trunc, "wb") as f:
            f.write(lk_header(0x7FFFFFFF, name=b"lk") + payload)  # claims 2 GiB, file is tiny
        lk = [f for f in run_json(trunc).get("findings", []) if f.get("type") == "mtk_lk"]
        check(len(lk) == 1 and lk[0]["confidence_tier"] != "consistent",
              "oversized payload stays below consistent tier")

    if fails:
        print(f"\nFAIL: {len(fails)} check(s) failed")
        return 1
    print("\nPASS: mtk_lk identify")
    return 0


if __name__ == "__main__":
    sys.exit(main())

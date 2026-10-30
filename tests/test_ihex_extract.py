#!/usr/bin/env python3
"""Intel HEX image-decode regression.

moria identifies Intel HEX but, before the ihex extractor, never materialized
the binary it programs, so mithril and moria's own recursion only ever saw hex
text. Under -e the extractor must reassemble the programmed bytes into the flat
image(s): contiguous bytes into one segment, a wide address gap into a separate
segment (anchored at its base), a small gap 0xFF-padded inside the segment.

Layers:
  1. Two regions (linear base 0 and 0x08000000) decode to two byte-exact files.
  2. A small intra-region gap (<= 16 bytes) is 0xFF-padded, staying one segment.
  3. A record with a bad checksum ends parsing (no garbage past it).

Deterministic and self-contained. Run: python3 tests/test_ihex_extract.py
"""
import glob
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")


def rec(rectype: int, addr: int, data: bytes, cksum_override=None) -> bytes:
    body = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, rectype]) + data
    ck = (-sum(body)) & 0xFF if cksum_override is None else cksum_override
    return (":" + body.hex().upper() + f"{ck:02X}" + "\r\n").encode()


def extract(data: bytes):
    """Run moria -e on `data`; return {filename: bytes} of produced image_*.bin."""
    with tempfile.TemporaryDirectory() as out:
        with tempfile.NamedTemporaryFile(suffix=".hex", delete=False) as tf:
            tf.write(data)
            path = tf.name
        try:
            subprocess.run([MORIA, "-e", "-C", out, path], capture_output=True, timeout=120)
        finally:
            os.unlink(path)
        found = {}
        for p in glob.glob(os.path.join(out, "**", "image_*.bin"), recursive=True):
            with open(p, "rb") as f:
                found[os.path.basename(p)] = f.read()
        return found


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # --- 1. two regions -> two byte-exact segments --------------------------
    segA = bytes(i % 256 for i in range(256))
    segB = bytes((i * 7 + 3) % 256 for i in range(64))
    hexdata = rec(0x04, 0, b"\x00\x00")  # linear base 0x00000000
    for off in range(0, len(segA), 16):
        hexdata += rec(0x00, off, segA[off:off + 16])
    hexdata += rec(0x04, 0, b"\x08\x00")  # linear base 0x08000000
    for off in range(0, len(segB), 16):
        hexdata += rec(0x00, off, segB[off:off + 16])
    hexdata += rec(0x01, 0, b"")  # EOF
    out = extract(hexdata)
    check("image_00000000.bin" in out, f"missing base-0 segment; got {sorted(out)}")
    check("image_08000000.bin" in out, f"missing base-0x08000000 segment; got {sorted(out)}")
    check(out.get("image_00000000.bin") == segA, "base-0 segment bytes differ")
    check(out.get("image_08000000.bin") == segB, "0x08000000 segment bytes differ")

    # --- 2. small intra-region gap is 0xFF-padded, stays one segment --------
    # Program 0x00..0x0F, skip 0x10..0x17 (8-byte gap <= PAD_TOL), then 0x18..0x27.
    gap = rec(0x04, 0, b"\x00\x00")
    gap += rec(0x00, 0x00, bytes(range(16)))
    gap += rec(0x00, 0x18, bytes(range(16)))
    gap += rec(0x01, 0, b"")
    gout = extract(gap)
    check(len(gout) == 1, f"gap: expected 1 segment, got {sorted(gout)}")
    exp = bytes(range(16)) + b"\xff" * 8 + bytes(range(16))
    check(gout.get("image_00000000.bin") == exp, "gap: 0xFF-padded bytes differ")

    # --- 3. a bad checksum ends parsing, no garbage past it -----------------
    bad = rec(0x04, 0, b"\x00\x00")
    bad += rec(0x00, 0x00, bytes(range(16)))                      # good
    bad += rec(0x00, 0x10, bytes(range(16)), cksum_override=0x00)  # corrupt checksum
    bad += rec(0x00, 0x20, bytes([0xAA] * 16))                    # must NOT appear
    bad += rec(0x01, 0, b"")
    bout = extract(bad)
    check(len(bout) == 1 and len(bout.get("image_00000000.bin", b"")) == 16,
          f"bad-checksum: expected 16 bytes before the bad record, got "
          f"{ {k: len(v) for k, v in bout.items()} }")
    check(b"\xaa" * 16 not in b"".join(bout.values()), "bad-checksum: bytes past the bad record leaked")

    if fails:
        for m in fails:
            print("FAIL [ihex-extract]:", m)
        return 1
    print("ok [ihex-extract]: segmentation, gap-pad, and checksum-stop all byte-exact")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""bzip2 identify regression: require the stream block magic, not just "BZh<n>".

The bzip2 signature used to accept any "BZh" followed by an ASCII block-size
digit (1-9) -- a 4-byte test. In a multi-megabyte opaque/compressed blob a
chance "BZh7"-style sequence satisfies that and was reported as bzip2, then
failed to decompress. A real bzip2 stream carries a 48-bit block magic right
after the 4-byte header: 0x314159265359 for the first compressed block, or the
end-of-stream magic 0x177245385090 when there are no blocks. Checking those six
bytes lifts the match from 4 bytes to 10 and removes the false positive.

Real streams come from Python's stdlib bz2 module, so no external tool is needed.

Run: python3 tests/test_bzip2.py [path-to-moria]
"""
import bz2
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


def bzip2_findings(data: bytes):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=120)
    doc = json.loads(r.stdout)
    return [x for x in doc.get("findings", []) if x["type"] == "bzip2"]


def main():
    payload = (b"The quick brown fox jumps over the lazy dog. " * 400)

    # 1) A genuine bzip2 stream (has the 0x314159265359 block magic) is identified,
    #    at offset 0 and at a realistic nonzero offset.
    real = bz2.compress(payload)
    check(real[:4] == b"BZh9", f"fixture: unexpected header {real[:4]!r}")
    check(real[4:10] == bytes.fromhex("314159265359"),
          f"fixture: expected block magic, got {real[4:10].hex()}")
    gs = bzip2_findings(real)
    check(len(gs) == 1 and gs[0]["offset"] == 0,
          f"real bzip2 at 0: expected one finding at 0, got {[(g['offset']) for g in gs]}")
    gs = bzip2_findings(b"\x00" * 0x400 + real)
    check(len(gs) == 1 and gs[0]["offset"] == 0x400,
          f"real bzip2 at 0x400: got {[(g['offset']) for g in gs]}")

    # 2) An empty bzip2 stream (no blocks -> end-of-stream magic 0x177245385090
    #    directly after the header) is still identified.
    empty = bz2.compress(b"")
    check(empty[4:10] == bytes.fromhex("177245385090"),
          f"fixture: expected EOS magic, got {empty[4:10].hex()}")
    gs = bzip2_findings(empty)
    check(len(gs) == 1, f"empty bzip2 stream: expected one finding, got {len(gs)}")

    # 3) FALSE-POSITIVE guard: "BZh" + a digit but NOT followed by the block magic
    #    must NOT be identified as bzip2. (This is the real tc7200 FP shape.)
    fp = b"BZh7" + bytes.fromhex("11c0e9878492") + os.urandom(4096)
    gs = bzip2_findings(fp)
    check(len(gs) == 0, f"FP guard: 'BZh7'+non-magic must not match, got {len(gs)}")

    # 4) FALSE-POSITIVE guard: valid 4-byte header + random where the next six bytes
    #    are random -> overwhelmingly rejected.
    hits = 0
    for i in range(64):
        blob = b"BZh" + bytes([0x31 + (i % 9)]) + os.urandom(64)
        hits += len(bzip2_findings(blob))
    check(hits == 0, f"FP guard: 64 random post-header blobs yielded {hits} bzip2 matches")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: bzip2 identify requires block magic (real + empty match; FP shapes rejected)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Legacy standalone LZMA (".lzma alone") identify + extract regression (issue #43).

moria must recognize a legacy LZMA1 "alone" stream (no magic number: a 13-byte
[props][dict_size][uncompressed_size] header, then a raw LZMA1 stream) and, under
-e, decompress it byte-exact. The format is anchored on the near-universal
firmware header prefix `5D 00 00` and confirmed by a trial-decode to a clean
end-of-stream marker, so the false-positive guards below are the point of the
whole exercise.

Real streams here come from Python's stdlib lzma module (FORMAT_ALONE), so the
"real stream" cases need no external tool.

Layers:
  1. Identify a genuine unknown-size .lzma stream -> verified.
  2. Extract byte-exact.
  3. Known-size header: correct declared size passes; wrong declared size rejected.
  4. FP guards: valid header + random payload rejected; a truncated stream (no end
     marker) rejected; a sub-threshold dict rejected.

Run: python3 tests/test_lzma.py
"""
import json
import lzma
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")


def moria_json(data: bytes, extra=None):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(data)
        f.flush()
        cmd = [MORIA, "-j"] + (extra or []) + [f.name]
        r = subprocess.run(cmd, capture_output=True, timeout=120)
    return json.loads(r.stdout)


def lzma_findings(data: bytes):
    return [x for x in moria_json(data).get("findings", []) if x["type"] == "lzma"]


def real_alone(payload: bytes) -> bytes:
    """A genuine unknown-size (0xFF...) .lzma-alone stream: props 0x5D, 8 MiB dict."""
    return lzma.compress(payload, format=lzma.FORMAT_ALONE)


def with_known_size(stream: bytes, size: int) -> bytes:
    """Patch the 8-byte uncompressed-size field (offset 5) to a definite value."""
    b = bytearray(stream)
    struct.pack_into("<Q", b, 5, size)
    return bytes(b)


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    payload = b"MORIA .lzma alone regression payload. " * 500  # ~19 KB, compressible
    stream = real_alone(payload)
    check(stream[:3] == b"\x5d\x00\x00", "fixture header not 5d 00 00 (unexpected liblzma default)")

    # --- 1. identify (unknown-size) -----------------------------------------
    g = lzma_findings(stream)
    check(len(g) == 1, f"identify: expected one lzma finding, got {len(g)}")
    if g:
        check(g[0]["confidence_tier"] == "verified", f"tier not verified: {g[0]['confidence_tier']}")
        check(str(len(payload)) in g[0].get("label", ""),
              f"decoded size not in label: {g[0].get('label')!r}")
        check(g[0]["offset"] == 0, "offset not 0")

    # --- 2. extract byte-exact ----------------------------------------------
    with tempfile.TemporaryDirectory() as t:
        img = os.path.join(t, "blob.lzma")
        with open(img, "wb") as f:
            f.write(stream)
        subprocess.run([MORIA, "-e", img], capture_output=True, timeout=120)
        dec = os.path.join(img + ".extracted", "0x0-lzma", "decompressed")
        check(os.path.exists(dec), "extract: decompressed file missing")
        if os.path.exists(dec):
            with open(dec, "rb") as f:
                got = f.read()
            check(got == payload, "extract: decompressed bytes are not byte-exact")

    # --- 3. known-size header: correct passes, wrong rejected ---------------
    good = with_known_size(stream, len(payload))
    gk = lzma_findings(good)
    check(len(gk) == 1, "known-size (correct) not identified")

    bad = with_known_size(stream, len(payload) + 7)  # off by a few bytes
    check(not lzma_findings(bad), "known-size mismatch was not rejected")

    # --- 4. false-positive guards -------------------------------------------
    # (a) valid header + random payload: the range coder cannot reach a clean
    #     end marker, so no finding.
    fp = b"\x5d\x00\x00\x00\x02" + b"\xff" * 8 + os.urandom(200000)
    check(not lzma_findings(fp), "FP: valid header + random payload was identified as lzma")

    # (b) truncated real stream (drop the tail incl. end marker): no clean end.
    trunc = stream[: len(stream) - 40]
    check(not lzma_findings(trunc), "FP: truncated lzma (no end marker) was identified")

    # (c) sub-threshold / non-power-of-two dict is rejected by the header check.
    baddict = bytearray(stream)
    struct.pack_into("<I", baddict, 1, 0x00000300)  # 768 B, below the 4 KiB floor
    # keep the 5d 00 00 anchor bytes intact for the scanner; only byte 3+ change
    baddict[1] = 0x00
    baddict[2] = 0x00
    check(not lzma_findings(bytes(baddict)), "FP: sub-threshold dict size was accepted")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: legacy .lzma identify (verified) + byte-exact extract + FP guards")
    return 0


if __name__ == "__main__":
    sys.exit(main())

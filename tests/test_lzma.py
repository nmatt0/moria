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
  5. Non-default props bytes (issue #45): streams built with (lc, lp, pb) other
     than the xz default must still be identified + extracted. The anchor is the
     format-invariant `00 00` (dict low 16 bits), not a fixed props value, so a
     props-0x6D OpenWrt-style stream at an offset is found byte-exact.

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
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")


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


def real_alone_props(payload: bytes, lc: int, lp: int, pb: int, dict_size: int = 8 << 20) -> bytes:
    """A genuine .lzma-alone stream with explicit (lc, lp, pb) -> arbitrary props byte."""
    filt = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}]
    c = lzma.LZMACompressor(format=lzma.FORMAT_ALONE, filters=filt)
    return c.compress(payload) + c.flush()


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

    # --- 5. non-default props bytes (issue #45) -----------------------------
    # The old anchor was the fixed prefix `5D 00 00`, so any stream with a props
    # byte other than 0x5D was invisible. Confirmed in the wild on OpenWrt ath79
    # (props 0x6D = lc1/lp2/pb2). The anchor is now the format-invariant `00 00`
    # (dict low 16 bits), so every valid (lc, lp, pb) is funneled to the validator.
    # liblzma's encoder enforces lc + lp <= 4; the validator's props <= 224 check
    # still covers the wider decode range, this just picks encoder-producible spread.
    props_cases = [
        (1, 2, 2),  # 0x6D — OpenWrt ath79 kernel, the reported case
        (0, 0, 2),  # 0x5A
        (2, 0, 2),  # 0x5C
        (4, 0, 4),  # 0xB8 — high props, well off the 0x5D default
    ]
    for lc, lp, pb in props_cases:
        props = (pb * 5 + lp) * 9 + lc
        s = real_alone_props(payload, lc, lp, pb)
        check(s[0] == props, f"props fixture byte mismatch for ({lc},{lp},{pb})")
        # place it at a nonzero offset, as in real firmware (kernel after a header)
        blob = b"\x00" * 0x200 + s
        gs = lzma_findings(blob)
        check(len(gs) == 1,
              f"props 0x{props:02x} ({lc},{lp},{pb}): expected one finding, got {len(gs)}")
        if gs:
            check(gs[0]["confidence_tier"] == "verified",
                  f"props 0x{props:02x}: tier {gs[0]['confidence_tier']}, want verified")
            check(gs[0]["offset"] == 0x200, f"props 0x{props:02x}: offset {gs[0]['offset']:#x}")

    # extract byte-exact for the reported OpenWrt (props 0x6D) case
    ow = real_alone_props(payload, 1, 2, 2)
    with tempfile.TemporaryDirectory() as t:
        img = os.path.join(t, "ow.lzma")
        with open(img, "wb") as f:
            f.write(ow)
        subprocess.run([MORIA, "-e", img], capture_output=True, timeout=120)
        dec = os.path.join(img + ".extracted", "0x0-lzma", "decompressed")
        check(os.path.exists(dec), "issue #45: props-0x6D extract produced no file")
        if os.path.exists(dec):
            with open(dec, "rb") as f:
                check(f.read() == payload, "issue #45: props-0x6D extract not byte-exact")

    # --- 6. low-entropy false positives (issue #74) -------------------------
    # The trial decode is NOT a sufficient FP guard in LOW-entropy data. Over a
    # run of zeros a minimal header (props 0x00, a declared 1-2 byte size) is
    # followed by zero bytes that the range coder decodes to that tiny size and a
    # clean end marker, so structured tables and flash padding produced storms of
    # bogus "Verified" findings (222 in one firmware's chip-ID table; 768 across
    # the corpus). The validator now rejects a compressed span dominated by a
    # single byte value. Real LZMA range-coder output is near-uniform, so this
    # drops every low-entropy FP and keeps every genuine stream.
    #
    # Faithful FP fixture: a minimal valid .lzma header inside zero padding. This
    # is the real on-flash shape, not an encoder's output (liblzma never emits a
    # zero-dominated stream), so it is built by hand.
    deg_hdr = bytes([0x00]) + struct.pack("<I", 0x10000) + struct.pack("<Q", 2)
    zero_region = b"\x00" * 0x100 + deg_hdr + b"\x00" * 0x100
    check(not lzma_findings(zero_region),
          "issue #74: zero-dominated region was identified as lzma (byte-dominance gate missing)")
    # An 0xFF flash-erase region behaves the same way; it must also stay quiet.
    ff_region = b"\xff" * 0x100 + bytes([0x00]) + struct.pack("<I", 0x10000) + \
        struct.pack("<Q", 2) + b"\x00" * 0x40
    check(not lzma_findings(ff_region),
          "issue #74: single-value-dominated region identified as lzma")
    # Critical TP guard: a SMALL real stream must survive. Its compressed span is
    # short, so a naive Shannon-entropy floor (which is capped at log2(len) on a
    # short span) would clip it; the byte-dominance test does not.
    for n in (256, 1024, 4096):
        small = real_alone(b"small real lzma payload, issue #74 guard. " * (n // 40 + 1))
        gs = lzma_findings(small)
        check(len(gs) == 1,
              f"issue #74: small real stream (~{len(small)}B span) dropped, got {len(gs)} findings")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: legacy .lzma identify (verified) + byte-exact extract + FP guards")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Ingenic jzlzma identify + extract regression (binwalk PR #957 format).

moria must recognize the "mark_rootfs_lzma" wrapper — U-Boot magic 0x27051956
stored little-endian at +4, so it can never collide with the big-endian uImage
header magic at +0 — around an Ingenic hardware-LZ77 stream, verify it by
trial-decoding exactly the declared uncompressed size, and under -e decompress
it byte-exact.

Fixtures are genuine streams from the greedy encoder in gen_samples.py
(mirroring src/extract/jzlzma.cpp), which exercises every opcode. The decoder
is additionally confirmed against stock Ingenic firmware during development
(Wansview A1 / Kiwibit BC111 T23ZN images: cpio rootfs payloads, byte-exact);
those files are too large to vendor here, so this gate uses the encoder.

Layers:
  1. Identify at a nonzero offset inside padding -> verified, exact size.
  2. Extract byte-exact; recursion opens a nested gzip payload inside.
  3. FP guards: plausible header + random payload, payload running past EOF,
     a declared size the stream cannot satisfy, zero sizes, and a corrupted
     magic are all rejected.

Run: python3 tests/test_jzlzma.py
"""
import gzip
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_samples  # noqa: E402

MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")


def moria_json(data: bytes, extra=None):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(data)
        f.flush()
        cmd = [MORIA, "-j"] + (extra or []) + [f.name]
        r = subprocess.run(cmd, capture_output=True, timeout=120)
    return json.loads(r.stdout)


def jzlzma_findings(data: bytes):
    return [x for x in moria_json(data).get("findings", []) if x["type"] == "jzlzma"]


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # --- 1. identify at a nonzero offset ------------------------------------
    payload = b"MORIA jzlzma regression payload. " * 300  # ~10 KB, compressible
    blob = gen_samples.jzlzma_stream(payload)
    pad = 0x1234
    image = b"\xff" * pad + blob + b"\x00" * 64  # trailing junk must not be claimed
    g = jzlzma_findings(image)
    check(len(g) == 1, f"identify: expected one jzlzma finding, got {len(g)}")
    if g:
        f = g[0]
        check(f["offset"] == pad, f"offset {f['offset']} != wrapper start {pad}")
        check(f["size"] == len(blob), f"size {f['size']} != {len(blob)}")
        check(f["confidence_tier"] == "verified", f"tier not verified: {f['confidence_tier']}")
        check(str(len(payload)) in f.get("label", ""), f"label missing size: {f.get('label')!r}")

    # --- 2. extract byte-exact + recursion ----------------------------------
    with tempfile.TemporaryDirectory() as out:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(image)
            path = tf.name
        subprocess.run([MORIA, "-e", "-C", out, path], capture_output=True, timeout=120)
        os.unlink(path)
        d = os.path.join(out, f"0x{pad:x}-jzlzma", "decompressed")
        check(os.path.exists(d), f"no decompressed output at {d}")
        if os.path.exists(d):
            got = open(d, "rb").read()
            check(got == payload, f"extract not byte-exact: {len(got)} vs {len(payload)} bytes")

    # A gzip payload inside jzlzma: -e must recurse and open it too.
    inner = b"nested gzip inside jzlzma. " * 100
    image2 = gen_samples.jzlzma_stream(gzip.compress(inner))
    with tempfile.TemporaryDirectory() as out:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(image2)
            path = tf.name
        subprocess.run([MORIA, "-e", "-C", out, path], capture_output=True, timeout=120)
        os.unlink(path)
        found_nested = False
        for root, _, files in os.walk(out):
            for name in files:
                if name == "decompressed" and root.endswith("gzip"):
                    if open(os.path.join(root, name), "rb").read() == inner:
                        found_nested = True
        check(found_nested, "nested gzip payload not extracted from jzlzma output")

    # --- 3. false-positive guards -------------------------------------------
    def header(payload_size, dict_size, uncomp, magic=0x27051956):
        return struct.pack("<IIII", payload_size, magic, dict_size, uncomp)

    # Plausible header, random "stream": the trial decode cannot produce 4 KB.
    rng = __import__("random").Random(1234)
    junk = bytes(rng.randrange(256) for _ in range(512))
    check(not jzlzma_findings(header(len(junk), 0x10000, 4096) + junk),
          "FP: random payload accepted")

    # Declared payload runs past EOF.
    stream = gen_samples.jzlzma_stream(b"short but real. " * 8)
    truncated = stream[:24]  # keep the header, clip most of the payload
    check(not jzlzma_findings(truncated), "FP: payload_size past EOF accepted")

    # Real stream, but the declared uncompressed size is one byte too many
    # (exactly the overrun the reference decoder needed patching around).
    tampered = bytearray(stream)
    struct.pack_into("<I", tampered, 12, len(b"short but real. " * 8) + 1)
    check(not jzlzma_findings(bytes(tampered)), "FP: unreachable declared size accepted")

    # Zero and oversized fields.
    z = bytearray(stream)
    struct.pack_into("<I", z, 12, 0)
    check(not jzlzma_findings(bytes(z)), "FP: uncomp_size 0 accepted")
    z = bytearray(stream)
    struct.pack_into("<I", z, 12, 0x10000001)
    check(not jzlzma_findings(bytes(z)), "FP: uncomp_size over cap accepted")

    # Corrupted magic: no jzlzma (and no uimage — the byte order differs).
    m = bytearray(stream)
    struct.pack_into("<I", m, 4, 0x27051957)
    check(not jzlzma_findings(bytes(m)), "FP: wrong magic accepted")

    # The wrapper must not be mistaken for a uImage despite sharing 0x27051956.
    check(not [x for x in moria_json(blob).get("findings", []) if x["type"] == "uimage"],
          "wrapper misidentified as uimage")

    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("test_jzlzma: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

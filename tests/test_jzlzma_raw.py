#!/usr/bin/env python3
"""Raw (unwrapped) Ingenic jzlzma regression: the dict+size mini-header form
found as the 'lzma' payload of uImages on T40/T41 (Wyze Cam v4).

moria must recognize [dict u32 LE][uncomp u32 LE][stream] with no wrapper,
trial-decode to exactly uncomp_size, and under -e decompress byte-exact.

Layers:
  1. Identify a raw stream at a nonzero offset -> verified, exact size.
  2. Extract byte-exact.
  3. Nested inside a uImage with ih_comp = 3: extractor must decode via the
     jzlzma fallback and warn (payload is jzlzma, not LZMA).
  4. FP guards: random payload, size+1 unreachable, past-EOF, zero fields,
     and no double-report when the same stream sits in a mark_rootfs_lzma
     wrapper.

Run: python3 tests/test_jzlzma_raw.py
"""
import binascii
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


def raw_stream(payload: bytes) -> bytes:
    """Genuine raw jzlzma encoding: [dict][uncomp][stream] (no wrapper)."""
    wrapped = gen_samples.jzlzma_stream(payload)  # 16-byte header + stream
    return wrapped[8:]  # strip payload_size + magic; keep dict + uncomp


def uimage_wrap(payload_stream: bytes) -> bytes:
    """A minimal legacy uImage (ih_comp=3, MIPS, os=5) around `payload_stream`.

    Header CRC must be valid for the uimage signature to reach the extractor.
    """
    name = b"raw-jzlzma-payload".ljust(32, b"\0")
    hdr = struct.pack(">IIIIIII4B32s", 0x27051956, 0, 0, len(payload_stream),
                      0x80100000, 0x80100000, 0, 5, 5, 2, 3, name)
    hcrc = binascii.crc32(hdr[:4] + b"\0\0\0\0" + hdr[8:]) & 0xFFFFFFFF
    hdr = hdr[:4] + struct.pack(">I", hcrc) + hdr[8:]
    dcrc = binascii.crc32(payload_stream) & 0xFFFFFFFF
    return hdr[:24] + struct.pack(">I", dcrc) + hdr[28:] + payload_stream


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def raw_findings(data: bytes):
        return [x for x in moria_json(data).get("findings", []) if x["type"] == "jzlzma-raw"]

    # --- 1. identify at a nonzero offset ------------------------------------
    payload = b"raw jzlzma regression payload. " * 300
    stream = raw_stream(payload)
    pad = 0x400
    image = b"\xff" * pad + stream + b"\x00" * 32
    g = raw_findings(image)
    check(len(g) == 1, f"identify: expected one jzlzma-raw finding, got {len(g)}")
    if g:
        f = g[0]
        check(f["offset"] == pad, f"offset {f['offset']} != {pad}")
        check(f["size"] == len(stream), f"size {f['size']} != {len(stream)}")
        check(f["confidence_tier"] == "verified", f"tier not verified: {f.get('confidence_tier')}")
        check(str(len(payload)) in f.get("label", ""), f"label missing size: {f.get('label')!r}")

    # --- 2. extract byte-exact ----------------------------------------------
    with tempfile.TemporaryDirectory() as out:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(image)
            path = tf.name
        subprocess.run([MORIA, "-e", "-C", out, path], capture_output=True, timeout=120)
        os.unlink(path)
        d = os.path.join(out, f"0x{pad:x}-jzlzma-raw", "decompressed")
        check(os.path.exists(d), f"no decompressed output at {d}")
        if os.path.exists(d):
            got = open(d, "rb").read()
            check(got == payload, f"extract not byte-exact: {len(got)} vs {len(payload)}")

    # --- 3. uImage with ih_comp = 3 wrapping a raw stream --------------------
    img = uimage_wrap(raw_stream(payload))
    with tempfile.TemporaryDirectory() as out:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(img)
            path = tf.name
        r = subprocess.run([MORIA, "-e", "-C", out, path], capture_output=True, timeout=180)
        os.unlink(path)
        manifest_path = os.path.join(out, "manifest.json")
        check(os.path.exists(manifest_path), "uImage: no manifest produced")
        if os.path.exists(manifest_path):
            m = open(manifest_path).read()
            check("jzlzma (not LZMA)" in m, "uImage fallback warning not emitted")
        # the decompressed payload must exist somewhere under the uimage dir
        # (uimage extractor writes ./payload for the decoded image)
        hit = False
        for root, _, files in os.walk(out):
            for name in ("payload", "decompressed"):
                if name in files:
                    p = os.path.join(root, name)
                    if open(p, "rb").read() == payload:
                        hit = True
        check(hit, "uImage jzlzma fallback did not decode the payload")

    # --- 4. false-positive guards -------------------------------------------
    rng = __import__("random").Random(777)
    junk = bytes(rng.randrange(256) for _ in range(2048))
    check(not raw_findings(struct.pack("<II", 0x10000, 4096) + junk),
          "FP: random payload accepted")
    real = raw_stream(b"short but real. " * 8)
    tampered = bytearray(real)
    struct.pack_into("<I", tampered, 4, struct.unpack_from("<I", real, 4)[0] + 1)
    check(not raw_findings(bytes(tampered)), "FP: unreachable declared size accepted")
    check(not raw_findings(real[:16]), "FP: stream past EOF accepted")
    z = bytearray(real)
    struct.pack_into("<I", z, 4, 0)
    check(not raw_findings(bytes(z)), "FP: uncomp_size 0 accepted")

    # Wrapped form must be owned by "jzlzma", not double-reported as raw.
    wrapped = gen_samples.jzlzma_stream(b"wrapped payload. " * 200)
    types = {x["type"] for x in moria_json(wrapped).get("findings", [])}
    check("jzlzma" in types, f"wrapped form not identified: {types}")
    check("jzlzma-raw" not in types, f"wrapped form double-reported as raw: {types}")

    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("test_jzlzma_raw: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Raw (unwrapped) Ingenic jzlzma: the dict+size mini-header form found as the
'lzma' payload of uImages on T40/T41 (Wyze Cam v4).

Raw jzlzma is a magicless, checksumless, non-entropy-coded bitstream, so it has
no standalone identity moria can gate without false positives: a run of 0x00
bytes decodes as an unbounded run of literal-zero opcodes that never errors, so
any region whose first bytes resemble a dict/size header followed by low-entropy
or zero-padded data (ubiquitous in firmware) "trial-decodes" to the declared
size. There is NO standalone jzlzma-raw scan signature for that reason. The raw
form is instead decoded only where a container tells us to expect it: a uImage
whose ih_comp = lzma whose payload fails a standard-LZMA decode.

Layers:
  1. uImage ih_comp = 3 wrapping a raw stream: the extractor decodes it via the
     jzlzma fallback and warns (payload is jzlzma, not LZMA).
  2. FP regression (the reason the standalone scanner was removed): low-entropy
     and zero-padded buffers carrying a plausible dict/size header must NOT
     produce any jzlzma finding, and the jzlzma-raw type must not exist at all.
  3. The wrapped form is still owned by the "jzlzma" signature (real magic), and
     a raw stream on its own is intentionally not identified as a finding.

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


def all_types(data: bytes):
    """Every finding type anywhere in the tree."""
    out = []

    def rec(nodes):
        for x in nodes:
            out.append(x.get("type"))
            rec(x.get("children", []) or [])

    rec(moria_json(data).get("findings", []))
    return out


def raw_stream(payload: bytes) -> bytes:
    """A genuine raw jzlzma encoding: [dict][uncomp][stream] (no wrapper)."""
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

    payload = b"raw jzlzma regression payload. " * 300

    # --- 1. uImage with ih_comp = 3 wrapping a raw stream -> fallback decode ---
    img = uimage_wrap(raw_stream(payload))
    with tempfile.TemporaryDirectory() as out:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(img)
            path = tf.name
        subprocess.run([MORIA, "-e", "-C", out, path], capture_output=True, timeout=180)
        os.unlink(path)
        manifest_path = os.path.join(out, "manifest.json")
        check(os.path.exists(manifest_path), "uImage: no manifest produced")
        if os.path.exists(manifest_path):
            m = open(manifest_path).read()
            check("jzlzma (not LZMA)" in m, "uImage fallback warning not emitted")
        hit = False
        for root, _, files in os.walk(out):
            for name in ("payload", "decompressed"):
                if name in files and open(os.path.join(root, name), "rb").read() == payload:
                    hit = True
        check(hit, "uImage jzlzma fallback did not decode the payload")

    # --- 2. FP regression: no standalone jzlzma-raw scanner -------------------
    # The exact shape that false-positived before the scanner was removed: a
    # plausible dict/size header (dict=64 KiB, uncomp=8192) in front of a run of
    # zeros. The old trial-decode "succeeded" (8192 literal zeros) and reported
    # a verified jzlzma-raw finding; moria must now find nothing jzlzma here.
    zero_fp = struct.pack("<II", 0x10000, 8192) + b"\x00" * 9300
    check(not any(t and t.startswith("jzlzma") for t in all_types(zero_fp)),
          "FP: zero-padded buffer with a dict/size header reported as jzlzma")

    # A real raw stream embedded at an offset is intentionally NOT identified on
    # its own any more (it is reached via its container, e.g. the uImage above).
    embedded = b"\xff" * 0x400 + raw_stream(payload) + b"\x00" * 32
    check("jzlzma-raw" not in all_types(embedded),
          "jzlzma-raw type still emitted (standalone scanner should be gone)")

    # High-entropy junk behind a header must also stay silent.
    rng = __import__("random").Random(777)
    junk = struct.pack("<II", 0x10000, 4096) + bytes(rng.randrange(256) for _ in range(6000))
    check("jzlzma-raw" not in all_types(junk), "FP: random payload reported as jzlzma-raw")

    # --- 3. wrapped form is still identified (real magic), never as raw -------
    wrapped = gen_samples.jzlzma_stream(b"wrapped payload. " * 200)
    types = set(all_types(wrapped))
    check("jzlzma" in types, f"wrapped form not identified: {types}")
    check("jzlzma-raw" not in types, f"wrapped form reported as raw: {types}")

    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("test_jzlzma_raw: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

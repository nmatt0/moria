#!/usr/bin/env python3
"""GIF/PNG findings must be sized to their real end, not to EOF (issue #58).

A GIF/PNG signature is magic-only in moria, so before the per-format validators a
finding with unknown size was back-filled by resolve() to the distance to the next
finding, or to EOF. A tiny image followed by unrelated bytes was therefore reported
as spanning everything after it (GIF over-reported ~2860x, PNG ~1450x on the
issue's repro), which mislabels trailing bytes as image and makes -c/-e carve the
padding. Both formats have a cheap deterministic terminator (GIF 0x3B, PNG IEND),
so the true size is computable.

This checks:
  1. A tiny GIF followed by 100000 padding bytes -> one gif finding whose size is
     the real image length, tier `consistent`.
  2. A tiny PNG followed by 100000 padding bytes -> one png finding whose size is
     the real image length, tier `verified` (every chunk CRC-32 checks out).
  3. Both at a nonzero offset (embedded asset) -> still sized to the real end.
  4. A truncated PNG (no IEND) is still identified, not dropped (the validator
     sizes, it must never reject a decisive magic).

Fixtures are built here with stdlib zlib/struct, so no external tool is needed.

Run: python3 tests/test_image_size.py
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")

PAD = 100000


def moria_findings(data: bytes):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=120)
    return json.loads(r.stdout).get("findings", [])


def findings_of(data: bytes, typ: str):
    return [x for x in moria_findings(data) if x["type"] == typ]


def tiny_gif() -> bytes:
    """A complete 1x1 GIF89a: header + LSD (no GCT) + image descriptor (no LCT) +
    a minimal LZW sub-block chain + the 0x3B trailer."""
    hdr = b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00"
    imgdesc = b"\x2c" + struct.pack("<HHHH", 0, 0, 1, 1) + b"\x00"
    img_data = b"\x02" + b"\x01\x4c" + b"\x00"
    return hdr + imgdesc + img_data + b"\x3b"


def _png_chunk(typ: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + typ + data +
            struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))


def tiny_png() -> bytes:
    """A complete 1x1 PNG: signature + IHDR + IDAT + IEND, every chunk CRC valid."""
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    idat = _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
    iend = _png_chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    gif = tiny_gif()
    png = tiny_png()

    # --- 1. GIF sized to its real end, not to EOF ---------------------------
    g = findings_of(gif + b"\x00" * PAD, "gif")
    check(len(g) == 1, f"gif: expected one finding, got {len(g)}")
    if g:
        check(g[0]["offset"] == 0, f"gif: offset {g[0]['offset']:#x}, want 0")
        check(g[0]["size"] == len(gif),
              f"gif: size {g[0]['size']} != real {len(gif)} (ran to EOF?)")
        check(g[0]["confidence_tier"] == "consistent",
              f"gif: tier {g[0]['confidence_tier']}, want consistent")

    # --- 2. PNG sized to its real end, verified via CRC ---------------------
    p = findings_of(png + b"\x00" * PAD, "png")
    check(len(p) == 1, f"png: expected one finding, got {len(p)}")
    if p:
        check(p[0]["offset"] == 0, f"png: offset {p[0]['offset']:#x}, want 0")
        check(p[0]["size"] == len(png),
              f"png: size {p[0]['size']} != real {len(png)} (ran to EOF?)")
        check(p[0]["confidence_tier"] == "verified",
              f"png: tier {p[0]['confidence_tier']}, want verified")

    # --- 3. embedded at a nonzero offset, still sized to the real end -------
    off = 0x400
    emb = b"\x00" * off + gif + b"\xff" * PAD
    g2 = findings_of(emb, "gif")
    check(len(g2) == 1 and g2[0]["offset"] == off and g2[0]["size"] == len(gif),
          f"gif embedded: {[(x['offset'], x['size']) for x in g2]} want [({off}, {len(gif)})]")

    emb2 = b"\x00" * off + png + b"\xff" * PAD
    p2 = findings_of(emb2, "png")
    check(len(p2) == 1 and p2[0]["offset"] == off and p2[0]["size"] == len(png),
          f"png embedded: {[(x['offset'], x['size']) for x in p2]} want [({off}, {len(png)})]")

    # --- 4. truncated PNG (no IEND) is still identified, not dropped --------
    trunc = png[: len(png) - 4]  # drop the IEND crc tail so the walk cannot finish
    pt = findings_of(trunc + b"\x00" * 2000, "png")
    check(len(pt) == 1, "png truncated: finding was dropped (validator must only size, not reject)")

    # --- 5. a stray GIF8 magic in binary data is rejected (not a GIF) --------
    # The 6-byte magic matches binary noise; a real GIF's first block after the
    # header+GCT is 0x2C/0x21/0x3B. This FP has 0x00 there (as seen in the wild),
    # so the validator must reject it rather than report a ~file-sized gif.
    fp = (b"GIF89a" + struct.pack("<HH", 5, 392) + b"\xf7\x22\x6f" +
          b"\x88" * 768 + b"\x00" * 50000)  # GCT flagged (768 B), then invalid 0x00 block
    gfp = findings_of(fp, "gif")
    check(len(gfp) == 0, f"gif FP: a non-GIF GIF89a magic was reported ({len(gfp)} findings)")

    # a truncated-but-real GIF (valid first block, no trailer) is NOT rejected
    tg = gif[: len(gif) - 1]  # drop the 0x3B trailer
    gt = findings_of(tg + b"\x00" * 2000, "gif")
    check(len(gt) == 1, "gif truncated: a real GIF without its trailer must not be dropped")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: GIF/PNG sized to the real terminator (not EOF); truncated still identified")
    return 0


if __name__ == "__main__":
    sys.exit(main())

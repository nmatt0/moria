#!/usr/bin/env python3
"""Artosyn OTRA firmware image identify + extract regression.

Covers both body layouts moria distinguishes:

  * segmented (VR04 goggles / air units): a partition table + a segment table,
    each partition being the concatenation of its LZO1X-compressed segments. The
    test builds a two-partition image from genuine LZO1X streams (produced offline
    from SYNTHETIC payloads — no vendor data), runs `moria -e`, and asserts each
    partition decompresses byte-for-byte via moria's own LZO decoder.
  * flat (arlink VT4 radio): no populated tables; the body is a raw flash image
    that moria writes out whole as flash.bin.

Both images carry a correct SHA-256 over the body (0x220..EOF), the firmware's own
integrity gate, so identification must reach the `verified` tier. Self-contained;
no external tools or libraries. Exit nonzero on any failure.
"""
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

# Two synthetic partition payloads and their genuine LZO1X-1 streams (liblzo2,
# lzo1x_1_compress), captured offline. moria's independent decoder must reproduce
# the plaintext exactly. These bytes are synthetic test data, not vendor firmware.
P0_PLAIN = b"MORIA-OTRA-TEST partition zero\n" * 40
P0_COMP = base64.b64decode(
    "AA1NT1JJQS1PVFJBLVRFU1QgcGFydGl0aW9uIHplcm8KIAAAAACPeAAKcnRpdGlvbiB6ZXJvChEAAA==")
P1_PLAIN = bytes((i * 37 + 11) & 0xFF for i in range(600))
P1_COMP = base64.b64decode(
    "APMLMFV6n8TpDjNYfaLH7BE2W4Clyu8UOV6DqM3yFzxhhqvQ9Ro/ZImu0/gdQmeMsdb7IEVqj7TZ/iN"
    "IbZK33AEmS3CVut8EKU5zmL3iByxRdpvA5QovVHmew+gNMld8ocbrEDVaf6TJ7hM4XYKnzPEWO2CFqs"
    "/0GT5jiK3S9xxBZouw1fofRGmOs9j9IkdskbbbACVKb5S53gMoTXKXvOEGK1B1mr/kCS5TeJ3C5wwxV"
    "nugxeoPNFl+o8jtEjdcgabL8BU6X4SpzvMYPWKHrNH2G0Bliq/U+R5DaI2y1/whRmuQtdr/JEluk7jd"
    "AidMcZa74AUqT3SZvuMILVJ3nMHmCzBVep8gACT8AwyYveIHLFF2m8DlCi9UeZ4RAAA=")

HDR = 0x220
HASH_OFF = 0x100
SIG_OFF = 0x120


def _finalize(buf):
    """Fill body_size @0x10 and SHA-256(body) @0x100; return immutable bytes."""
    struct.pack_into("<I", buf, 0x10, len(buf) - HDR)
    buf[HASH_OFF:HASH_OFF + 0x20] = hashlib.sha256(bytes(buf[HDR:])).digest()
    return bytes(buf)


def _header(npart, nseg, region1=0, region2=0, compress=1, version=b"1.0.0"):
    b = bytearray(HDR)
    b[0:4] = b"OTRA"
    b[0x04] = 1              # version byte
    b[0x05] = compress       # compress flag
    b[0x0a] = 0x20           # hashsize
    struct.pack_into("<H", b, 0x0e, 0x100)   # siglen
    struct.pack_into("<I", b, 0x18, region1)
    struct.pack_into("<I", b, 0x1c, region2)
    struct.pack_into("<H", b, 0x20, npart)
    struct.pack_into("<H", b, 0x22, nseg)
    b[0x80:0x80 + len(version)] = version
    # 0x120..0x220 signature: left zero (moria verifies the SHA-256, not the RSA)
    return b


def build_segmented():
    parts = [(b"P0", 0x10000, 0x10000, 1), (b"P1", 0x20000, 0x10000, 0)]
    segs_meta = [(P0_COMP, len(P0_PLAIN), 0x10000), (P1_COMP, len(P1_PLAIN), 0x20000)]
    b = _header(len(parts), len(segs_meta))
    # partition table (npart x 0x34)
    for name, flash_off, cap, flags in parts:
        e = bytearray(0x34)
        e[0:len(name)] = name
        struct.pack_into("<Q", e, 0x20, flash_off)
        struct.pack_into("<Q", e, 0x28, cap)
        struct.pack_into("<I", e, 0x30, flags)
        b += e
    pay_off = HDR + len(parts) * 0x34 + len(segs_meta) * 0x20
    # segment table (nseg x 0x20) + payloads
    cur = pay_off
    payloads = b""
    seg_tbl = b""
    for comp, ulen, flash_off in segs_meta:
        e = bytearray(0x20)
        struct.pack_into("<Q", e, 0x00, cur)          # file_off
        struct.pack_into("<Q", e, 0x08, flash_off)    # flash_off
        struct.pack_into("<Q", e, 0x10, len(comp))    # data_len (compressed)
        struct.pack_into("<Q", e, 0x18, ulen)         # flash_len (decompressed)
        seg_tbl += e
        payloads += comp
        cur += len(comp)
    b += seg_tbl + payloads
    return _finalize(b)


def build_flat():
    # region1 present, no usable tables -> flat subtype. npart/nseg are set but the
    # segment chain does not validate (file_off 0), so moria treats the body as raw.
    body_extra = bytes((i * 13 + 7) & 0xFF for i in range(0x400))
    b = _header(1, 1, region1=0x40, compress=0, version=b"9.9.9")
    b += bytes(0x54)     # one zeroed part entry (0x34) + one zeroed seg entry (0x20)
    b += body_extra
    return _finalize(b), body_extra


def moria_json(path):
    r = subprocess.run([MORIA, "-j", path], capture_output=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"moria exited {r.returncode}: {r.stderr.decode(errors='replace')}")
    return json.loads(r.stdout)


def main():
    fails = []
    with tempfile.TemporaryDirectory() as tmp:
        # ---- segmented ----
        seg_img = os.path.join(tmp, "seg.img")
        with open(seg_img, "wb") as f:
            f.write(build_segmented())
        j = moria_json(seg_img)
        top = j["findings"][0] if j["findings"] else {}
        if top.get("type") != "otra":
            fails.append(f"segmented: type={top.get('type')} (want otra)")
        if top.get("confidence_tier") != "verified":
            fails.append(f"segmented: tier={top.get('confidence_tier')} (want verified; SHA-256)")
        if top.get("compression") != "lzo1x":
            fails.append(f"segmented: compression={top.get('compression')} (want lzo1x)")
        if len(top.get("members", [])) != 2:
            fails.append(f"segmented: members={len(top.get('members', []))} (want 2)")

        outdir = os.path.join(tmp, "seg.out")
        subprocess.run([MORIA, "-e", seg_img, "-C", outdir], capture_output=True, timeout=60)
        root = os.path.join(outdir, "0x0-otra")
        expect = {"00_P0.bin": P0_PLAIN, "01_P1.bin": P1_PLAIN}
        for fname, want in expect.items():
            p = os.path.join(root, fname)
            if not os.path.exists(p):
                fails.append(f"segmented: missing extracted {fname}")
                continue
            got = open(p, "rb").read()
            if got != want:
                fails.append(f"segmented: {fname} not byte-exact "
                             f"({len(got)} bytes, sha {hashlib.sha256(got).hexdigest()[:12]})")

        # ---- flat ----
        flat_img = os.path.join(tmp, "flat.img")
        img_bytes, body = build_flat()
        with open(flat_img, "wb") as f:
            f.write(img_bytes)
        j = moria_json(flat_img)
        top = j["findings"][0] if j["findings"] else {}
        if top.get("type") != "otra":
            fails.append(f"flat: type={top.get('type')} (want otra)")
        if top.get("confidence_tier") != "verified":
            fails.append(f"flat: tier={top.get('confidence_tier')} (want verified)")
        if top.get("compression") != "none":
            fails.append(f"flat: compression={top.get('compression')} (want none)")

        outdir = os.path.join(tmp, "flat.out")
        subprocess.run([MORIA, "-e", flat_img, "-C", outdir], capture_output=True, timeout=60)
        fb = os.path.join(outdir, "0x0-otra", "flash.bin")
        if not os.path.exists(fb):
            fails.append("flat: flash.bin missing")
        else:
            got = open(fb, "rb").read()
            if got != img_bytes[HDR:]:
                fails.append("flat: flash.bin does not equal the image body")
            elif got[-len(body):] != body:
                fails.append("flat: flash.bin body tail mismatch")

    if fails:
        print("FAIL:")
        for m in fails:
            print("  -", m)
        return 1
    print("PASS: OTRA segmented (2 partitions, LZO byte-exact) + flat (flash.bin) round-trip; "
          "both verified via SHA-256")
    return 0


if __name__ == "__main__":
    sys.exit(main())

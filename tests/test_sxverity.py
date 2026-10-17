#!/usr/bin/env python3
"""sxverity container identify regression (issue #55).

moria must name the SpaceX "sxverity" dm-verity container, not just the romfs
payload it wraps. The container is a 4 KiB preamble of four 1024-byte records
(each starting with the ASCII magic "sxverity") followed by a big-endian romfs
at 0x1000. Before this signature, moria reported only the romfs at offset 4096
and left the 4 KiB header as an unnamed gap.

Checks:
  1. A synthetic container -> a `sxverity` finding at offset 0 covering the 4 KiB
     record table (tier consistent), with the romfs surfaced as its own finding
     at 0x1000, so the summary names the container.
  2. The container found at a nonzero offset (embedded in a larger flash image).
  3. FP guards: a lone "sxverity" string without the four-record + romfs
     structure is not reported (the romfs volume name is itself "sxverity").
  4. Optional: real sxverity images, if a directory of them is pointed to via
     $MORIA_SXVERITY_SAMPLES (self-skips otherwise, so CI stays self-contained
     with no sample path baked in). Any file in that dir starting with the magic
     is checked, so no specific filename is assumed.

Run: python3 tests/test_sxverity.py
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")


def moria_findings(data: bytes):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=120)
    return json.loads(r.stdout).get("findings", [])


def findings_of(data: bytes, typ: str):
    return [x for x in moria_findings(data) if x["type"] == typ]


def romfs(size: int = 256) -> bytes:
    b = bytearray(size)
    b[0:8] = b"-rom1fs-"
    struct.pack_into(">I", b, 8, size)  # full_size, big-endian
    b[16:24] = b"sxverity"              # volume name (as on the real device)
    return bytes(b)


def container(payload: bytes = None) -> bytes:
    if payload is None:
        payload = romfs()
    rec = bytearray(1024)
    rec[0:8] = b"sxverity"
    struct.pack_into("<I", rec, 0x0c, 0x800)
    rec[0x20:0x40] = bytes(range(0x20, 0x40))
    return bytes(rec) * 4 + payload


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    img = container()

    # --- 1. identify the container, name the 4 KiB record table --------------
    sx = findings_of(img, "sxverity")
    check(len(sx) == 1, f"expected one sxverity finding, got {len(sx)}")
    if sx:
        check(sx[0]["offset"] == 0, f"sxverity offset {sx[0]['offset']:#x}, want 0")
        check(sx[0]["size"] == 4096, f"sxverity size {sx[0]['size']}, want 4096 (record table)")
        check(sx[0]["confidence_tier"] == "consistent",
              f"sxverity tier {sx[0]['confidence_tier']}, want consistent")
    rf = findings_of(img, "romfs")
    check(len(rf) == 1 and rf[0]["offset"] == 4096,
          f"romfs payload not surfaced at 0x1000: {[(x['offset']) for x in rf]}")

    # --- 2. embedded at a nonzero offset ------------------------------------
    off = 0x10000
    emb = b"\x00" * off + img
    sxe = findings_of(emb, "sxverity")
    check(len(sxe) == 1 and sxe[0]["offset"] == off and sxe[0]["size"] == 4096,
          f"embedded sxverity: {[(x['offset'], x['size']) for x in sxe]} want [({off}, 4096)]")

    # --- 3. FP guards -------------------------------------------------------
    # (a) a lone magic with no record table / payload
    check(not findings_of(b"sxverity" + b"\x00" * 5000, "sxverity"),
          "FP: a lone sxverity magic was reported")
    # (b) the magic present but the romfs payload missing after four records
    no_payload = (bytes(bytearray(b"sxverity" + b"\x00" * 1016)) * 4) + b"\x00" * 4096
    check(not findings_of(no_payload, "sxverity"),
          "FP: four records without a romfs payload were accepted")
    # (c) only one record (no repeat at 0x400) then a romfs
    one_rec = b"sxverity" + b"\x00" * 1016 + romfs() + b"\x00" * 4096
    check(not findings_of(one_rec, "sxverity"),
          "FP: a single record (no four-record table) was accepted")

    # --- 4. optional real images (opt-in via env, no path baked in) ---------
    ran_real = 0
    sample_dir = os.environ.get("MORIA_SXVERITY_SAMPLES")
    if sample_dir and os.path.isdir(sample_dir):
        for name in sorted(os.listdir(sample_dir)):
            p = os.path.join(sample_dir, name)
            if not os.path.isfile(p):
                continue
            with open(p, "rb") as f:
                head = f.read(8)
            if head != b"sxverity":  # only files that actually start with the magic
                continue
            with open(p, "rb") as f:
                data = f.read()
            ran_real += 1
            sr = findings_of(data, "sxverity")
            check(len(sr) == 1 and sr[0]["offset"] == 0 and sr[0]["size"] == 4096 and
                  sr[0]["confidence_tier"] == "consistent",
                  f"real sample: sxverity not identified as expected: {sr}")
            check(any(x["offset"] == 4096 for x in findings_of(data, "romfs")),
                  "real sample: romfs payload not at 0x1000")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    tail = f"(+{ran_real} real images)" if ran_real else "(real samples opt-in via $MORIA_SXVERITY_SAMPLES)"
    print(f"PASS: sxverity container identify + payload + FP guards {tail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

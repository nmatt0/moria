#!/usr/bin/env python3
"""Philips Sonicare ".upg" firmware container identification + extraction regression.

Builds synthetic .upg containers, runs `moria -e -j`, and asserts:
  1. Normal case: identified as type "sonicare_upg" with verified confidence
     (header+payload+trailer spans file exactly AND tag matches), label
     recovered, header.bin/payload.bin/trailer.bin round-trip byte-for-byte.
  2. Label-OOB regression: when payload_size < 24, the label must NOT be
     sourced from bytes outside the container (issue review blocker #1).
  3. Tag-mismatch: wrong tag -> consistent, not verified.

Self-contained synthetic fixtures; no real firmware involved. Exit nonzero on
any failure.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")

HEADER_LEN = 0x38
LABEL = b"TESTBOOT"
OPAQUE_PREFIX = bytes((i * 31 + 7) & 0xFF for i in range(16))
FIXED_TAG = bytes.fromhex("0100140102000000")
PAYLOAD_FILLER = bytes((i * 197 + 13) & 0xFF for i in range(500))
TRAILER = bytes((i * 53 + 1) & 0xFF for i in range(16))


def build_normal():
    """Normal container: full payload with tag + label."""
    payload = OPAQUE_PREFIX + FIXED_TAG + LABEL + b"\x00" * 8 + PAYLOAD_FILLER
    header = (
        b"\xFCUPH" +
        b"\xFF\xFF\xFF\xFF" +
        struct.pack("<I", len(payload)) +
        struct.pack("<H", 1) +
        struct.pack("<H", HEADER_LEN) +
        bytes(HEADER_LEN - 16)
    )
    return header, payload, TRAILER


def build_tiny_payload():
    """Payload smaller than kPreLabel (24): label must be suppressed, not read
    from outside the container."""
    payload = b"P" * 8  # 8 bytes, well under 24
    header = (
        b"\xFCUPH" +
        b"\xFF\xFF\xFF\xFF" +
        struct.pack("<I", len(payload)) +
        struct.pack("<H", 1) +
        struct.pack("<H", HEADER_LEN) +
        bytes(HEADER_LEN - 16)
    )
    trailer = bytes(16)
    # Append bait text AFTER the container to catch an OOB label read.
    bait = b"NOT_PART_OF_CONTAINER\x00" + b"\xff" * 200
    return header, payload, trailer, bait


def build_bad_tag():
    """Correct size arithmetic but wrong 8-byte tag -> consistent, not verified."""
    bad_tag = bytes.fromhex("deadbeefdeadbeef")
    payload = OPAQUE_PREFIX + bad_tag + b"FAKELBL\x00" + PAYLOAD_FILLER
    header = (
        b"\xFCUPH" +
        b"\xFF\xFF\xFF\xFF" +
        struct.pack("<I", len(payload)) +
        struct.pack("<H", 1) +
        struct.pack("<H", HEADER_LEN) +
        bytes(HEADER_LEN - 16)
    )
    return header, payload, TRAILER


def run_moria(blob, tmp, tag):
    p = os.path.join(tmp, f"{tag}.upg")
    with open(p, "wb") as f:
        f.write(blob)
    outdir = os.path.join(tmp, f"out_{tag}")
    r = subprocess.run([MORIA, "-e", "-j", p, "-C", outdir], capture_output=True, timeout=60)
    if r.returncode != 0:
        print(f"FAIL[{tag}]: moria exited {r.returncode}", r.stderr.decode(errors="replace"))
        return None, None
    return json.loads(r.stdout), outdir


def test_normal(tmp):
    header, payload, trailer = build_normal()
    j, outdir = run_moria(header + payload + trailer, tmp, "normal")
    if j is None:
        return 1
    fails = []

    findings = [x for x in j.get("findings", []) if x.get("type") == "sonicare_upg"]
    if not findings:
        print("FAIL[normal]: no sonicare_upg finding")
        return 1
    f = findings[0]
    if f.get("confidence_tier") != "verified":
        fails.append(f"confidence_tier={f.get('confidence_tier')} (want verified)")
    if f.get("label") != LABEL.decode():
        fails.append(f"label={f.get('label')!r} (want {LABEL.decode()!r})")

    ex = [e for e in j.get("extraction", {}).get("extracted", []) if e.get("type") == "sonicare_upg"]
    if not ex:
        fails.append("no sonicare_upg extraction")
    else:
        e = ex[0]
        if e.get("status") != "ok":
            fails.append(f"status={e.get('status')}")
        if e.get("files") != 3:
            fails.append(f"files={e.get('files')} (want 3)")
        root = os.path.join(outdir, e["root"])
        for name, want in [("header.bin", header), ("payload.bin", payload), ("trailer.bin", trailer)]:
            fp = os.path.join(root, name)
            if not os.path.exists(fp):
                fails.append(f"missing {name}")
            elif open(fp, "rb").read() != want:
                fails.append(f"{name} content mismatch")

    if fails:
        for m in fails:
            print(f"  FAIL[normal]: {m}")
        return 1
    print("  PASS  sonicare_upg normal: verified, label recovered, 3 pieces round-trip")
    return 0


def test_label_oob(tmp):
    header, payload, trailer, bait = build_tiny_payload()
    blob = header + payload + trailer + bait
    j, _ = run_moria(blob, tmp, "label_oob")
    if j is None:
        return 1

    findings = [x for x in j.get("findings", []) if x.get("type") == "sonicare_upg"]
    if not findings:
        print("FAIL[label_oob]: no sonicare_upg finding")
        return 1
    f = findings[0]
    label = f.get("label", "")
    if "NOT_PART_OF_CONTAINER" in label:
        print(f"  FAIL[label_oob]: label={label!r} — read from outside the container!")
        return 1
    # With payload_size=8 < kPreLabel=24, label should be empty.
    if label:
        print(f"  FAIL[label_oob]: label={label!r} — expected empty for tiny payload")
        return 1
    print("  PASS  sonicare_upg label_oob: tiny payload does not leak label from outside")
    return 0


def test_bad_tag(tmp):
    header, payload, trailer = build_bad_tag()
    j, _ = run_moria(header + payload + trailer, tmp, "bad_tag")
    if j is None:
        return 1

    findings = [x for x in j.get("findings", []) if x.get("type") == "sonicare_upg"]
    if not findings:
        print("FAIL[bad_tag]: no sonicare_upg finding")
        return 1
    f = findings[0]
    tier = f.get("confidence_tier", "")
    if tier == "verified":
        print(f"  FAIL[bad_tag]: confidence_tier=verified despite wrong tag")
        return 1
    if tier != "consistent":
        print(f"  FAIL[bad_tag]: confidence_tier={tier} (want consistent)")
        return 1
    print("  PASS  sonicare_upg bad_tag: wrong tag -> consistent, not verified")
    return 0


def main():
    with tempfile.TemporaryDirectory() as tmp:
        rc = 0
        rc |= test_normal(tmp)
        rc |= test_label_oob(tmp)
        rc |= test_bad_tag(tmp)
        if rc == 0:
            print("PASS")
        return rc


if __name__ == "__main__":
    sys.exit(main())

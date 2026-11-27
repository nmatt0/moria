#!/usr/bin/env python3
"""Philips Sonicare ".upg" firmware container identification + extraction regression.

Fixtures carry the format's real 236-byte plaintext payload header (16 opaque
bytes, the constant 8-byte tag, three 64-byte NUL-padded ASCII fields, a
12-byte component record), then a stand-in for the encrypted body.

Cases:
  1. normal        exact EOF span + tag -> verified, label recovered,
                   header.bin/payload.bin/trailer.bin round-trip byte-for-byte,
                   sonicare_upg-info.txt records the plaintext header.
  2. embedded      byte-identical container followed by padding -> consistent
                   (the tag still counts when the container is not the whole
                   file, which is the normal case for one pulled out of an APK
                   or a flash dump).
  3. bad_tag       exact EOF span, wrong tag -> consistent, not verified.
  4. label_oob     payload_size < 24: the label must not be sourced from the
                   trailer or from past the container (review blocker #1).
  5. label_no_nul  64 printable bytes with no terminator is not this field;
                   the label must be suppressed rather than reported as 64
                   characters of whatever was printable.
  6. undersized    payload_size below the 236-byte plaintext header trips the
                   soft constraint -> magic tier, no size claim, no extraction.

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
PLAIN_HEADER = 0xEC
LABEL = b"TESTBOOT"
STRING2 = b"TESTBOOT Connected"
STRING3 = b"application FW"
COMPONENT = b"boot2nd"
OPAQUE_PREFIX = bytes((i * 31 + 7) & 0xFF for i in range(16))
FIXED_TAG = bytes.fromhex("0100140102000000")
BODY = bytes((i * 197 + 13) & 0xFF for i in range(500))
TRAILER = bytes((i * 53 + 1) & 0xFF for i in range(16))


def header_for(payload_len):
    return (b"\xFCUPH" +
            b"\xFF\xFF\xFF\xFF" +
            struct.pack("<I", payload_len) +
            struct.pack("<H", 1) +
            struct.pack("<H", HEADER_LEN) +
            bytes(HEADER_LEN - 16))


def plain_header(tag=FIXED_TAG, label=LABEL, label_field=None):
    """The 236-byte plaintext payload header. `label_field` overrides the raw
    64 bytes of the name field, for the no-terminator case."""
    name = label_field if label_field is not None else label.ljust(64, b"\x00")
    assert len(name) == 64
    return (OPAQUE_PREFIX + tag + name +
            STRING2.ljust(64, b"\x00") +
            STRING3.ljust(64, b"\x00") +
            struct.pack("<II", 1, 0x1000) +
            COMPONENT.ljust(8, b"\x00") +
            struct.pack("<I", 1))


def build(tag=FIXED_TAG, label=LABEL, label_field=None, body=BODY):
    payload = plain_header(tag, label, label_field) + body
    assert len(payload) >= PLAIN_HEADER
    return header_for(len(payload)), payload, TRAILER


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


def findings_of(j):
    return [x for x in j.get("findings", []) if x.get("type") == "sonicare_upg"]


def test_normal(tmp):
    header, payload, trailer = build()
    j, outdir = run_moria(header + payload + trailer, tmp, "normal")
    if j is None:
        return 1
    fails = []

    fs = findings_of(j)
    if not fs:
        print("FAIL[normal]: no sonicare_upg finding")
        return 1
    f = fs[0]
    if f.get("confidence_tier") != "verified":
        fails.append(f"confidence_tier={f.get('confidence_tier')} (want verified)")
    if f.get("label") != LABEL.decode():
        fails.append(f"label={f.get('label')!r} (want {LABEL.decode()!r})")
    if f.get("size") != len(header) + len(payload) + len(trailer):
        fails.append(f"size={f.get('size')} (want {len(header) + len(payload) + len(trailer)})")

    ex = [e for e in j.get("extraction", {}).get("extracted", [])
          if e.get("type") == "sonicare_upg"]
    if not ex:
        fails.append("no sonicare_upg extraction")
    else:
        e = ex[0]
        if e.get("status") != "ok":
            fails.append(f"status={e.get('status')}")
        if e.get("files") != 4:
            fails.append(f"files={e.get('files')} (want 4: 3 pieces + info sidecar)")
        root = os.path.join(outdir, e["root"])
        for name, want in [("header.bin", header), ("payload.bin", payload),
                           ("trailer.bin", trailer)]:
            fp = os.path.join(root, name)
            if not os.path.exists(fp):
                fails.append(f"missing {name}")
            elif open(fp, "rb").read() != want:
                fails.append(f"{name} content mismatch")
        info_p = os.path.join(root, "sonicare_upg-info.txt")
        if not os.path.exists(info_p):
            fails.append("missing sonicare_upg-info.txt")
        else:
            info = open(info_p, encoding="utf-8").read()
            for want in (LABEL.decode(), STRING2.decode(), STRING3.decode(),
                         COMPONENT.decode(), FIXED_TAG.hex()):
                if want not in info:
                    fails.append(f"info sidecar missing {want!r}")
            if str(len(payload) - PLAIN_HEADER) not in info:
                fails.append("info sidecar does not record the encrypted body size")

    if fails:
        for m in fails:
            print(f"  FAIL[normal]: {m}")
        return 1
    print("  PASS  sonicare_upg normal: verified, label, 3 pieces round-trip + info sidecar")
    return 0


def test_embedded(tmp):
    """A byte-identical container that is not the whole file. The tag is the
    format's own self-check, so it must still carry the finding above the
    structural floor (compare otra/vbf, where the internal check drives the
    tier and EOF is secondary)."""
    header, payload, trailer = build()
    blob = header + payload + trailer + b"\x00" * 4096
    j, _ = run_moria(blob, tmp, "embedded")
    if j is None:
        return 1
    fs = findings_of(j)
    if not fs:
        print("FAIL[embedded]: no sonicare_upg finding")
        return 1
    f = fs[0]
    tier = f.get("confidence_tier")
    if tier != "consistent":
        print(f"  FAIL[embedded]: confidence_tier={tier} (want consistent)")
        return 1
    if f.get("size") != len(header) + len(payload) + len(trailer):
        print(f"  FAIL[embedded]: size={f.get('size')} (want the container, not the file)")
        return 1
    if f.get("label") != LABEL.decode():
        print(f"  FAIL[embedded]: label={f.get('label')!r}")
        return 1
    print("  PASS  sonicare_upg embedded: tag carries it to consistent, size is the container")
    return 0


def test_bad_tag(tmp):
    header, payload, trailer = build(tag=bytes.fromhex("deadbeefdeadbeef"), label=b"FAKELBL")
    j, _ = run_moria(header + payload + trailer, tmp, "bad_tag")
    if j is None:
        return 1
    fs = findings_of(j)
    if not fs:
        print("FAIL[bad_tag]: no sonicare_upg finding")
        return 1
    tier = fs[0].get("confidence_tier")
    if tier != "consistent":
        print(f"  FAIL[bad_tag]: confidence_tier={tier} (want consistent)")
        return 1
    print("  PASS  sonicare_upg bad_tag: wrong tag -> consistent, not verified")
    return 0


def test_label_oob(tmp):
    """payload_size below kPreLabel (24). The label must not come from the
    trailer or from the bait text after the container."""
    payload = b"P" * 8
    blob = (header_for(len(payload)) + payload + bytes(16) +
            b"NOT_PART_OF_CONTAINER\x00" + b"\xff" * 200)
    j, _ = run_moria(blob, tmp, "label_oob")
    if j is None:
        return 1
    fs = findings_of(j)
    if not fs:
        # The soft constraint may reject it outright, which is also correct: the
        # point is that no label is sourced from outside the container.
        print("  PASS  sonicare_upg label_oob: no finding, nothing leaked")
        return 0
    label = fs[0].get("label") or ""
    if "NOT_PART_OF_CONTAINER" in label:
        print(f"  FAIL[label_oob]: label={label!r} read from outside the container")
        return 1
    if label:
        print(f"  FAIL[label_oob]: label={label!r} expected empty for a tiny payload")
        return 1
    print("  PASS  sonicare_upg label_oob: tiny payload does not leak a label")
    return 0


def test_label_no_nul(tmp):
    """The name field is a fixed 64 bytes, NUL-padded. 64 printable bytes with
    no terminator is not that field, so no label."""
    header, payload, trailer = build(label_field=b"A" * 64)
    j, _ = run_moria(header + payload + trailer, tmp, "label_no_nul")
    if j is None:
        return 1
    fs = findings_of(j)
    if not fs:
        print("FAIL[label_no_nul]: no sonicare_upg finding")
        return 1
    label = fs[0].get("label") or ""
    if label:
        print(f"  FAIL[label_no_nul]: label={label!r} (want none: no NUL in the field)")
        return 1
    print("  PASS  sonicare_upg label_no_nul: unterminated field yields no label")
    return 0


def test_undersized(tmp):
    """payload_size below the 236-byte plaintext header: the soft constraint
    downgrades to magic tier with soft_evidence and the validator never runs, so
    the finding makes no `verified`/`consistent` claim. Extraction still splits
    the pieces that are genuinely in the file (the house pattern: the extractor
    reports what it found), but the info sidecar is skipped because the
    plaintext header it would serialize is not there."""
    payload = OPAQUE_PREFIX + FIXED_TAG + b"SHORT\x00\x00\x00"
    blob = header_for(len(payload)) + payload + TRAILER
    j, outdir = run_moria(blob, tmp, "undersized")
    if j is None:
        return 1
    fs = findings_of(j)
    if not fs:
        print("  PASS  sonicare_upg undersized: rejected outright")
        return 0
    f = fs[0]
    fails = []
    if f.get("confidence_tier") != "magic":
        fails.append(f"confidence_tier={f.get('confidence_tier')} (want magic)")
    if "payload_size too small" not in (f.get("evidence") or ""):
        fails.append(f"evidence={f.get('evidence')!r} (want the soft-constraint reason)")
    ex = [e for e in j.get("extraction", {}).get("extracted", [])
          if e.get("type") == "sonicare_upg"]
    if ex:
        root = os.path.join(outdir, ex[0]["root"])
        if os.path.exists(os.path.join(root, "sonicare_upg-info.txt")):
            fails.append("info sidecar written for a payload with no plaintext header")
        if ex[0].get("files") != 3:
            fails.append(f"files={ex[0].get('files')} (want 3: pieces only, no sidecar)")
    if fails:
        for m in fails:
            print(f"  FAIL[undersized]: {m}")
        return 1
    print("  PASS  sonicare_upg undersized: magic tier via soft constraint, no info sidecar")
    return 0


def main():
    with tempfile.TemporaryDirectory() as tmp:
        rc = 0
        rc |= test_normal(tmp)
        rc |= test_embedded(tmp)
        rc |= test_bad_tag(tmp)
        rc |= test_label_oob(tmp)
        rc |= test_label_no_nul(tmp)
        rc |= test_undersized(tmp)
        if rc == 0:
            print("PASS")
        return rc


if __name__ == "__main__":
    sys.exit(main())

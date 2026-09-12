#!/usr/bin/env python3
"""".upg" firmware container identification + extraction regression.

Builds a synthetic .upg (56-byte header, payload with a 16-byte opaque prefix,
a constant 8-byte tag, then a NUL-padded ASCII label, then filler; 16-byte
trailer), runs `moria -e -j`, and asserts: the container is identified as type
"upg" with verified confidence (header_length + payload_size + 16 spans the
file exactly) and the embedded label is recovered; and that
header.bin/payload.bin/trailer.bin round-trip byte-for-byte. Self-contained
synthetic fixture; no real firmware involved. Exit nonzero on any failure.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

HEADER_LEN = 0x38
LABEL = b"TESTBOOT"
OPAQUE_PREFIX = bytes((i * 31 + 7) & 0xFF for i in range(16))  # stand-in nonce/digest
FIXED_TAG = bytes.fromhex("0100140102000000")  # observed constant across every real sample
PAYLOAD_FILLER = bytes((i * 197 + 13) & 0xFF for i in range(500))  # stand-in for the encrypted body
TRAILER = bytes((i * 53 + 1) & 0xFF for i in range(16))


def build_upg():
    payload = OPAQUE_PREFIX + FIXED_TAG + LABEL + b"\x00" * 8 + PAYLOAD_FILLER
    header = (
        b"\xFCUPH" +                              # magic
        b"\xFF\xFF\xFF\xFF" +                      # reserved
        struct.pack("<I", len(payload)) +          # payload_size
        struct.pack("<H", 1) +                     # format_version
        struct.pack("<H", HEADER_LEN) +            # header_length
        bytes(HEADER_LEN - 16)                     # pad to header_length
    )
    return header, payload, TRAILER


def main():
    header, payload, trailer = build_upg()
    upg_bytes = header + payload + trailer
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "fw.upg")
        with open(p, "wb") as f:
            f.write(upg_bytes)
        outdir = os.path.join(tmp, "out")
        r = subprocess.run([MORIA, "-e", "-j", p, "-C", outdir], capture_output=True, timeout=60)
        if r.returncode != 0:
            print("FAIL: moria exited", r.returncode, r.stderr.decode(errors="replace"))
            return 1
        j = json.loads(r.stdout)

        fails = []

        findings = [x for x in j.get("findings", []) if x.get("type") == "upg"]
        if not findings:
            print("FAIL: no upg finding in output")
            return 1
        finding = findings[0]
        if finding.get("confidence_tier") != "verified":
            fails.append(f"confidence_tier={finding.get('confidence_tier')} (want verified)")
        if finding.get("label") != LABEL.decode():
            fails.append(f"label={finding.get('label')!r} (want {LABEL.decode()!r})")

        ex = [e for e in j.get("extraction", {}).get("extracted", []) if e.get("type") == "upg"]
        if not ex:
            fails.append("no upg extraction in output")
        else:
            e = ex[0]
            if e.get("status") != "ok":
                fails.append(f"status={e.get('status')} (want ok); warnings={e.get('warnings')}")
            if e.get("files") != 3:
                fails.append(f"files={e.get('files')} (want 3)")
            root = os.path.join(outdir, e["root"])
            expect = {"header.bin": header, "payload.bin": payload, "trailer.bin": trailer}
            for name, want in expect.items():
                fp = os.path.join(root, name)
                if not os.path.exists(fp):
                    fails.append(f"missing {name}")
                    continue
                got = open(fp, "rb").read()
                if got != want:
                    fails.append(f"{name}: {len(got)} bytes, want {len(want)} (content mismatch)")

        if fails:
            for m in fails:
                print("  FAIL:", m)
            return 1
        print("  PASS  upg: identified (verified, label recovered) + 3 pieces round-trip")
        print("PASS")
        return 0


if __name__ == "__main__":
    sys.exit(main())

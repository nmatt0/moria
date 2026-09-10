#!/usr/bin/env python3
"""RAE Systems / Honeywell RFP extraction regression.

Builds a synthetic RFP with a stored section and a real LZARI-compressed section
(a genuine compressed RFP section captured from firmware, with its known plaintext),
runs `moria -e`, and asserts every section round-trips: stored copied verbatim,
LZARI decoded byte-for-byte. Self-contained; no external tools. Exit nonzero on
any failure.
"""
import base64
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

# A real LZARI-compressed RFP section (RigRat "ExtendIniFile") and its exact
# plaintext. The 4-byte stream prefix (0x000000e3 = 227) is the decoded size.
LZARI_COMP = base64.b64decode(
    "4wAAALWZC5Dxky2ghp9/GtVf5wimDn7I2ux/zQdTIQJD4JPNaKqoq8wWHBAdgk/A+wQl8rR3A6KHs1k"
    "L1zkVmwmtMruRGA72mzSU6Irklsl03H6XcAKLH02985uhavJiKziwo8JniyzaVQ9LFEFbfqMkXkNt/L"
    "/mWr2poUyIhLKynnhCvwz6WMWKO1MJQF7qxKEfaWbp7A==")
LZARI_PLAIN = (b"[Package]\r\nName=RigRat\r\nVersion=\r\nUpgradeSequence=RFP2,RFP1\r\n"
               b"FirmwareCount=2\r\n"
               b"RFP1=d:\\firmware\\build\\RAEF-LAMRFP-JOB1\\tools\\..\\output\\LAM_Application.RFP\r\n"
               b"RFP2=d:\\firmware\\build\\RAEF-LAMRFP-JOB1\\tools\\..\\output\\LAM_Sensor.RFP\r\n")

INI = b"; synthetic\r\n"
SIGN = bytes(96)


def section(name, flags, usize, data):
    return struct.pack("<I", len(name)) + name + struct.pack("<III", flags, usize, len(data)) + data


def build_rfp():
    hdr = (b"RAE Systems Inc." + struct.pack("<H", 1) + struct.pack("<I", 0) + b"RAE" + bytes(16))
    return (hdr +
            section(b"IniFile", 0, len(INI), INI) +
            section(b"ExtendIniFile", 1, len(LZARI_PLAIN), LZARI_COMP) +
            section(b"SIGN", 0, len(SIGN), SIGN))


def main():
    assert len(LZARI_PLAIN) == 227
    with tempfile.TemporaryDirectory() as tmp:
        rfp = os.path.join(tmp, "fw.rfp")
        with open(rfp, "wb") as f:
            f.write(build_rfp())
        outdir = os.path.join(tmp, "out")
        r = subprocess.run([MORIA, "-e", "-j", rfp, "-C", outdir], capture_output=True, timeout=60)
        if r.returncode != 0:
            print("FAIL: moria exited", r.returncode, r.stderr.decode(errors="replace"))
            return 1
        j = json.loads(r.stdout)

        ex = [e for e in j.get("extraction", {}).get("extracted", []) if e.get("type") == "rae_rfp"]
        if not ex:
            print("FAIL: no rae_rfp extraction in output")
            return 1
        e = ex[0]
        fails = []
        if e.get("status") != "ok":
            fails.append(f"status={e.get('status')} (want ok); warnings={e.get('warnings')}")
        if e.get("files") != 3:
            fails.append(f"files={e.get('files')} (want 3)")

        root = os.path.join(outdir, e["root"])
        expect = {"IniFile": INI, "ExtendIniFile": LZARI_PLAIN, "SIGN": SIGN}
        for name, want in expect.items():
            p = os.path.join(root, name)
            if not os.path.exists(p):
                fails.append(f"missing section file {name}")
                continue
            got = open(p, "rb").read()
            if got != want:
                fails.append(f"{name}: {len(got)} bytes, want {len(want)} (content mismatch)")

        if fails:
            for m in fails:
                print("  FAIL:", m)
            return 1
        print(f"  PASS  RFP: 3 sections round-trip (stored + LZARI-decoded {len(LZARI_PLAIN)}B)")
        print("PASS")
        return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""VFW firmware container extraction regression.

Builds synthetic VFW containers with known payloads and CRC-32 checksums,
runs `moria -e`, and asserts the payload round-trips byte-for-byte with the
correct output filename and status. Self-contained; no external tools. Exit
nonzero on any failure.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")


def build_vfw(magic, payload):
    """Build a VFW container: 8-byte magic + u32 LE payload_size + u32 LE CRC-32 + payload."""
    assert len(magic) == 8
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    return magic + struct.pack("<II", len(payload), crc) + payload


def run(vfw_bytes, expect_name, expect_payload, tag):
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "fw.vfw")
        with open(p, "wb") as f:
            f.write(vfw_bytes)
        outdir = os.path.join(tmp, "out")
        r = subprocess.run([MORIA, "-e", "-j", p, "-C", outdir], capture_output=True, timeout=60)
        if r.returncode != 0:
            print(f"FAIL[{tag}]: moria exited", r.returncode, r.stderr.decode(errors="replace"))
            return 1
        j = json.loads(r.stdout)
        ex = [e for e in j.get("extraction", {}).get("extracted", []) if e.get("type") == "vfw"]
        if not ex:
            print(f"FAIL[{tag}]: no vfw extraction in output")
            return 1
        e = ex[0]
        fails = []
        if e.get("status") != "ok":
            fails.append(f"status={e.get('status')} (want ok); warnings={e.get('warnings')}")
        if e.get("files") != 1:
            fails.append(f"files={e.get('files')} (want 1)")
        root = os.path.join(outdir, e["root"])
        fp = os.path.join(root, expect_name)
        if not os.path.exists(fp):
            fails.append(f"missing {expect_name}")
        else:
            got = open(fp, "rb").read()
            if got != expect_payload:
                fails.append(f"{expect_name}: {len(got)} bytes, want {len(expect_payload)} (content mismatch)")
        if fails:
            for m in fails:
                print(f"  FAIL[{tag}]:", m)
            return 1
        print(f"  PASS  VFW {tag}: payload round-trip ok")
        return 0


def test_identify(vfw_bytes, expect_tier, tag):
    """Run moria in identify-only mode and check tier + type."""
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "fw.vfw")
        with open(p, "wb") as f:
            f.write(vfw_bytes)
        r = subprocess.run([MORIA, "-j", p], capture_output=True, timeout=60)
        if r.returncode != 0:
            print(f"FAIL[{tag}]: moria exited", r.returncode, r.stderr.decode(errors="replace"))
            return 1
        j = json.loads(r.stdout)
        findings = j.get("findings", [])
        vfw_findings = [f for f in findings if f.get("type") == "vfw"]
        if not vfw_findings:
            print(f"FAIL[{tag}]: no vfw finding")
            return 1
        f = vfw_findings[0]
        if f.get("confidence_tier") != expect_tier:
            print(f"FAIL[{tag}]: tier={f.get('confidence_tier')} (want {expect_tier})")
            return 1
        print(f"  PASS  VFW {tag}: tier={expect_tier}")
        return 0


def main():
    rc = 0

    # MCU payload: component "MCU", variant "F1"
    mcu_payload = bytes((i * 7 + 3) & 0xFF for i in range(512))
    rc |= run(build_vfw(b"VFWMCUF1", mcu_payload), "MCU_F1.bin", mcu_payload, "mcu")

    # BLE payload: component "BLE", variant "F1"
    ble_payload = bytes((i * 13 + 1) & 0xFF for i in range(256))
    rc |= run(build_vfw(b"VFWBLEF1", ble_payload), "BLE_F1.bin", ble_payload, "ble")

    # GPS payload: component "GPS", variant "D2"
    gps_payload = bytes((i * 31 + 5) & 0xFF for i in range(1024))
    rc |= run(build_vfw(b"VFWGPSD2", gps_payload), "GPS_D2.bin", gps_payload, "gps")

    # Identification tiers: verified (good CRC), consistent (bad CRC, exact EOF)
    rc |= test_identify(build_vfw(b"VFWMCUF1", mcu_payload), "verified", "id-verified")

    bad_crc = b"VFWMCUF1" + struct.pack("<II", len(mcu_payload), 0xDEADBEEF) + mcu_payload
    rc |= test_identify(bad_crc, "consistent", "id-consistent")

    if rc == 0:
        print("PASS")
    return rc


if __name__ == "__main__":
    sys.exit(main())

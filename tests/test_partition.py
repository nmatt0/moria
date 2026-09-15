#!/usr/bin/env python3
"""GPT / MBR partition-table identification + region-map regression (issue #21).

Two layers:
  1. Synthetic, always-on: hand-built GPT (correct CRC32s) and MBR tables, plus
     false-positive negatives (a bare protective MBR, a random 0x55AA trailer).
  2. Real-tool round-trip: build actual disks with sgdisk / sfdisk when present,
     assert moria maps the partitions. Self-skips cleanly if the tools are absent.

Run: python3 tests/test_partition.py
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")
sys.path.insert(0, HERE)
import gen_samples  # noqa: E402


def moria_json(data: bytes):
    with tempfile.NamedTemporaryFile(suffix=".img") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=60)
    return json.loads(r.stdout)


def find(findings, t):
    return [f for f in findings if f["type"] == t]


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # --- synthetic GPT --------------------------------------------------------
    d = moria_json(gen_samples.gpt_disk())["findings"]
    g = find(d, "gpt")
    check(len(g) == 1, "GPT: expected exactly one gpt finding")
    if g:
        check(g[0]["confidence_tier"] == "verified", "GPT: not verified (CRC check failed?)")
        mem = {m["name"]: m for m in g[0].get("members", [])}
        check(set(mem) == {"ESP", "rootfs"}, f"GPT: partition names wrong: {sorted(mem)}")
        check(mem.get("ESP", {}).get("note") == "EFI System", "GPT: ESP type GUID not decoded")
        check(mem.get("rootfs", {}).get("note") == "Linux filesystem", "GPT: Linux type not decoded")
        check(mem.get("ESP", {}).get("offset") == 34 * 512, "GPT: ESP offset wrong")
    # A GPT disk carries a protective MBR; it must be rejected (GPT owns the map).
    check(not find(d, "mbr"), "GPT: protective MBR was not rejected")

    # --- synthetic MBR --------------------------------------------------------
    d = moria_json(gen_samples.mbr_disk())["findings"]
    m = find(d, "mbr")
    check(len(m) == 1, "MBR: expected exactly one mbr finding")
    if m:
        check(m[0]["confidence_tier"] in ("consistent", "verified"), "MBR: tier too low")
        mem = m[0].get("members", [])
        check(len(mem) == 3, f"MBR: expected 3 partitions, got {len(mem)}")
        notes = " ".join(x.get("note", "") for x in mem)
        check("FAT32" in notes and "Linux" in notes, f"MBR: type bytes not decoded: {notes}")
        check(mem[1].get("offset") == 41 * 512, "MBR: partition 2 offset wrong")

    # --- false positives ------------------------------------------------------
    # Bare protective MBR (0xEE spanning disk), no GPT -> no partition finding.
    prot = bytearray(400 * 512)
    struct.pack_into("<B", prot, 0x1BE + 4, 0xEE)
    struct.pack_into("<I", prot, 0x1BE + 8, 1)
    struct.pack_into("<I", prot, 0x1BE + 12, 399)
    prot[0x1FE], prot[0x1FF] = 0x55, 0xAA
    d = moria_json(bytes(prot))["findings"]
    check(not find(d, "mbr") and not find(d, "gpt"), "bare protective MBR should yield no table")

    # Random data ending in 0x55AA (invalid boot flags) -> not an MBR.
    junk = bytearray((i * 37 + 11) & 0xFF for i in range(4096))
    junk[0x1FE], junk[0x1FF] = 0x55, 0xAA
    # force at least one invalid boot flag so it can never look like a table
    junk[0x1BE] = 0x33
    d = moria_json(bytes(junk))["findings"]
    check(not find(d, "mbr"), "random 0x55AA trailer must not be flagged as MBR")

    # --- real-tool round-trips (self-skip) ------------------------------------
    if shutil.which("sgdisk"):
        with tempfile.TemporaryDirectory() as t:
            img = os.path.join(t, "g.img")
            with open(img, "wb") as f:
                f.truncate(64 * 1024 * 1024)
            subprocess.run(["sgdisk", "-og", img], capture_output=True, check=True)
            subprocess.run(["sgdisk", "-n", "1:2048:+8M", "-t", "1:EF00", "-c", "1:boot", img],
                           capture_output=True, check=True)
            subprocess.run(["sgdisk", "-n", "2:0:+8M", "-t", "2:8300", "-c", "2:rootfs", img],
                           capture_output=True, check=True)
            with open(img, "rb") as f:
                d = moria_json(f.read())["findings"]
            g = find(d, "gpt")
            check(bool(g) and g[0]["confidence_tier"] == "verified", "real sgdisk GPT not verified")
            if g:
                names = {m["name"] for m in g[0].get("members", [])}
                check({"boot", "rootfs"} <= names, f"real GPT names missing: {names}")
    else:
        print("  (sgdisk absent — real GPT round-trip skipped)")

    if shutil.which("sfdisk"):
        with tempfile.TemporaryDirectory() as t:
            img = os.path.join(t, "m.img")
            with open(img, "wb") as f:
                f.truncate(64 * 1024 * 1024)
            script = "label: dos\nunit: sectors\n2048,16384,83\n18432,16384,6\n"
            subprocess.run(["sfdisk", img], input=script.encode(), capture_output=True, check=True)
            with open(img, "rb") as f:
                d = moria_json(f.read())["findings"]
            mm = find(d, "mbr")
            check(bool(mm), "real sfdisk MBR not identified")
            if mm:
                check(len(mm[0].get("members", [])) == 2, "real MBR partition count wrong")
    else:
        print("  (sfdisk absent — real MBR round-trip skipped)")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: GPT/MBR identify + region map (synthetic CRC-checked, FP-guarded, "
          "real-tool round-trips)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

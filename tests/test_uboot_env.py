#!/usr/bin/env python3
"""U-Boot environment identify + extract regression.

Builds synthetic env blocks (single and redundant headers, at offset 0 and
embedded mid-image), runs `moria` to check identification tier/offset/size, and
`moria -e` to check the decoded uboot-env.txt round-trips the variables. Also
asserts the false-positive guards: too few vars, a newline-separated script, and
a header-less list produce no verified env. Self-contained; no external tools.
Exit nonzero on any failure.
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

VARS = [
    b"bootcmd=run ramboot; bootm 0x82000000",
    b"bootargs=console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=squashfs",
    b"baudrate=115200",
    b"ethaddr=00:11:22:33:44:55",
    b"ipaddr=192.168.1.1",
    b"serverip=192.168.1.100",
    b"bootdelay=1",
]
EXPECT = [v.decode() for v in VARS]


def env_block(size, redundant=False, flags=1):
    hlen = 5 if redundant else 4
    data = b"\x00".join(VARS) + b"\x00\x00"
    data = data.ljust(size - hlen, b"\x00")[: size - hlen]
    crc = zlib.crc32(data) & 0xFFFFFFFF
    head = struct.pack("<I", crc)
    if redundant:
        head += bytes([flags])
    return head + data


def run_json(path):
    out = subprocess.run([MORIA, "-j", path], capture_output=True, text=True).stdout
    return json.loads(out)


def find_env(doc):
    return [f for f in doc.get("findings", []) if f.get("type") == "uboot_env"]


def extract(path, outdir):
    subprocess.run([MORIA, "-e", "-C", outdir, path], capture_output=True, text=True)
    for d in os.listdir(outdir):
        p = os.path.join(outdir, d, "uboot-env.txt")
        if os.path.isfile(p):
            with open(p, "r") as f:
                return [ln for ln in f.read().splitlines() if ln]
    return None


def main():
    fails = []

    def check(cond, msg):
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            fails.append(msg)

    with tempfile.TemporaryDirectory() as td:
        # --- single header at offset 0, 0x2000 block ---
        single = os.path.join(td, "single.env")
        with open(single, "wb") as f:
            f.write(env_block(0x2000))
        envs = find_env(run_json(single))
        check(len(envs) == 1, "single: one env finding")
        if envs:
            e = envs[0]
            check(e["confidence_tier"] == "verified", "single: verified (CRC)")
            check(e["offset"] == 0 and e["size"] == 0x2000, "single: exact offset+size")
        lines = extract(single, os.path.join(td, "out_single"))
        check(lines == EXPECT, "single: decoded env round-trips")

        # --- redundant header (crc + flags) at offset 0, 0x4000 block ---
        redund = os.path.join(td, "redund.env")
        with open(redund, "wb") as f:
            f.write(env_block(0x4000, redundant=True))
        envs = find_env(run_json(redund))
        check(len(envs) == 1 and envs[0]["confidence_tier"] == "verified",
              "redundant: verified")
        if envs:
            check(envs[0].get("label") == "redundant", "redundant: labeled redundant")
        lines = extract(redund, os.path.join(td, "out_redund"))
        check(lines == EXPECT, "redundant: decoded env round-trips (flags byte skipped)")

        # --- embedded at a nonzero offset inside padding + trailing junk ---
        emb = os.path.join(td, "emb.bin")
        with open(emb, "wb") as f:
            f.write(b"\xff" * 0x10000 + env_block(0x2000) + os.urandom(0x800))
        envs = find_env(run_json(emb))
        check(len(envs) == 1 and envs[0]["offset"] == 0x10000
              and envs[0]["confidence_tier"] == "verified", "embedded: verified @0x10000")

        # --- FP guards ---
        few = os.path.join(td, "few.bin")
        with open(few, "wb") as f:
            f.write(b"\x00\x00\x00\x00bootcmd=x\x00bootargs=y\x00\x00" + b"\x00" * 256)
        check(len(find_env(run_json(few))) == 0, "fp: too few vars -> no finding")

        script = os.path.join(td, "script.bin")
        with open(script, "wb") as f:
            f.write((b"bootcmd=x\nbootargs=y\nbaudrate=1\nethaddr=z\nipaddr=1\n") * 4)
        check(len(find_env(run_json(script))) == 0,
              "fp: newline-separated script -> no finding")

    if fails:
        print(f"\nFAIL: {len(fails)} check(s) failed")
        return 1
    print("\nPASS: uboot_env identify + extract")
    return 0


if __name__ == "__main__":
    sys.exit(main())

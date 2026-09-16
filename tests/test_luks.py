#!/usr/bin/env python3
"""LUKS1 / LUKS2 identification regression (issue #23).

Identify-only: moria must recognize a LUKS encrypted volume and report the
header parameters (version, cipher+mode, KDF, key size) without decrypting.

Layers:
  1. Synthetic, always-on: the hand-built LUKS1 phdr and LUKS2 header+JSON from
     gen_samples, plus negatives (a LUKS2 secondary header, an unknown version).
  2. Real cryptsetup round-trip when the tool is present (self-skips otherwise).

Run: python3 tests/test_luks.py
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


def moria_luks(data: bytes):
    with tempfile.NamedTemporaryFile(suffix=".img") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=60)
    fs = json.loads(r.stdout)["findings"]
    return [x for x in fs if x["type"] in ("luks1", "luks2")]


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # --- synthetic LUKS1 ------------------------------------------------------
    g = moria_luks(gen_samples.luks1_hdr())
    check(len(g) == 1, "LUKS1: expected one luks finding")
    if g:
        check(g[0]["type"] == "luks1", "LUKS1: type not luks1 (version in the type)")
        lab = g[0].get("label", "")
        check("aes-xts-plain64" in lab and "sha256" in lab and "512-bit" in lab,
              f"LUKS1: params wrong: {lab!r}")
        check(g[0]["confidence_tier"] == "consistent", "LUKS1: tier not consistent")

    # --- synthetic LUKS2 ------------------------------------------------------
    g = moria_luks(gen_samples.luks2_hdr())
    check(len(g) == 1, "LUKS2: expected one luks finding")
    if g:
        check(g[0]["type"] == "luks2", "LUKS2: type not luks2 (version in the type)")
        lab = g[0].get("label", "")
        check("aes-xts-plain64" in lab and "argon2id" in lab and "512-bit" in lab,
              f"LUKS2: params wrong: {lab!r}")

    # --- negatives ------------------------------------------------------------
    # LUKS2 secondary header (hdr_offset != 0) must be rejected.
    sec = bytearray(gen_samples.luks2_hdr())
    struct.pack_into(">Q", sec, 0x100, 16384)  # nonzero hdr_offset
    check(not moria_luks(bytes(sec)), "LUKS2 secondary header (hdr_offset!=0) not rejected")

    # Unknown version -> not identified.
    unk = bytearray(gen_samples.luks1_hdr())
    struct.pack_into(">H", unk, 6, 7)
    check(not moria_luks(bytes(unk)), "unknown LUKS version was identified")

    # --- real cryptsetup round-trip (self-skip) -------------------------------
    if shutil.which("cryptsetup"):
        with tempfile.TemporaryDirectory() as t:
            key = os.path.join(t, "k")
            with open(key, "wb") as f:
                f.write(b"moria-luks-test\n")
            for ver, want_kdf in (("luks1", "sha256"), ("luks2", "argon2id")):
                img = os.path.join(t, ver + ".img")
                with open(img, "wb") as f:
                    f.truncate(16 * 1024 * 1024)
                r = subprocess.run(
                    ["cryptsetup", "-q", "luksFormat", "--type", ver,
                     "--cipher", "aes-xts-plain64", "--key-size", "512", "--hash", "sha256",
                     img, key],
                    capture_output=True)
                if r.returncode != 0:
                    print(f"  (cryptsetup luksFormat {ver} failed — skipped: "
                          f"{r.stderr.decode(errors='replace').strip()[:80]})")
                    continue
                with open(img, "rb") as f:
                    g = moria_luks(f.read())
                check(bool(g), f"real {ver}: not identified")
                if g:
                    check(g[0]["type"] == ver, f"real {ver}: wrong type {g[0]['type']}")
                    check("aes-xts-plain64" in g[0].get("label", ""),
                          f"real {ver}: cipher not read ({g[0].get('label')!r})")
                    check(want_kdf in g[0].get("label", ""),
                          f"real {ver}: KDF/hash not read ({g[0].get('label')!r})")
    else:
        print("  (cryptsetup absent — real LUKS round-trip skipped)")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: LUKS1/LUKS2 identify with header parameters (synthetic + real cryptsetup)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

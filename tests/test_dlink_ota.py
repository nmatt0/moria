#!/usr/bin/env python3
"""D-Link OTA container identify + descramble regression.

The container is [u32 build][u32 count][count x 24-byte entries]; each entry is
{"OTAn", u32 0x18, u32 cksum, u32 size, u32 payload_off, u32 flags}. Payloads
tile forward from just after the entry table and the last ends at EOF. Each
payload is a Realtek Ameba firmware image (magic "81958711") obfuscated with a
single-byte XOR. moria derives the key from the magic and verifies it, so the
scheme is keyless and self-validating.

This test builds synthetic containers (no corpus bytes) and checks:
  1. a valid container is identified as dlink_ota (verified) and -e writes the
     de-XORed payload (byte-exact, starts with the Ameba magic);
  2. the key is DERIVED, not hardcoded -- a payload XORed with a non-0xab key
     still decrypts;
  3. FP guards: a bare "OTA1" with no valid entry table is not identified; a
     structurally valid container whose payload is not an Ameba image is not
     "decryptable" (no descrambled.bin emitted).

Run: python3 tests/test_dlink_ota.py [path-to-moria]
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")
AMEBA = b"81958711"

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


def container(payloads, build=0x30190412):
    """payloads: list of raw (already-XORed) payload bytes. Returns the container."""
    count = len(payloads)
    hdr_end = 8 + count * 24
    entries = b""
    off = hdr_end
    body = b""
    for i, pl in enumerate(payloads):
        tag = ("OTA%d" % (i + 1)).encode()
        entries += tag + struct.pack("<IIIII", 0x18, 0, len(pl), off, 0)
        body += pl
        off += len(pl)
    return struct.pack("<II", build, count) + entries + body


def ameba_payload(key, body_after_magic=b"\x00" * 24 + b"AMEBA-TEST-IMAGE", size=512):
    """A synthetic Ameba image (magic + filler) XORed with `key`."""
    pt = AMEBA + body_after_magic
    pt = pt + b"\x00" * (size - len(pt))
    return bytes(b ^ key for b in pt)


def moria_json(data, extra=None):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j"] + (extra or []) + [f.name], capture_output=True, timeout=120)
    return json.loads(r.stdout)


def ota_findings(data):
    return [x for x in moria_json(data).get("findings", []) if x["type"] == "dlink_ota"]


def extract(data):
    """Run -e; return the descrambled.bin bytes if produced, else None."""
    with tempfile.TemporaryDirectory() as t:
        img = os.path.join(t, "ota.bin")
        with open(img, "wb") as f:
            f.write(data)
        out = os.path.join(t, "out")
        subprocess.run([MORIA, "-e", "-C", out, img], capture_output=True, timeout=120)
        for dp, _, fs in os.walk(out):
            if "descrambled.bin" in fs:
                return open(os.path.join(dp, "descrambled.bin"), "rb").read()
    return None


def main():
    # 1. Valid 2-slot container, real key 0xab -> identified + byte-exact de-XOR.
    pt = AMEBA + b"\x00" * 24 + b"AMEBA-TEST-IMAGE" + b"\x00" * 464
    obf = bytes(b ^ 0xAB for b in pt)
    data = container([obf, obf])
    gs = ota_findings(data)
    check(len(gs) == 1 and gs[0]["offset"] == 0, f"valid container: expected one finding at 0, got {gs}")
    if gs:
        check(gs[0]["confidence_tier"] == "verified",
              f"valid container tier={gs[0]['confidence_tier']}, want verified")
        check(gs[0]["size"] == len(data), f"size {gs[0]['size']} != container {len(data)}")
    dec = extract(data)
    check(dec is not None and dec[:8] == AMEBA, "extract: descrambled.bin missing or wrong magic")
    check(dec == pt, "extract: de-XOR not byte-exact")

    # 2. Key is DERIVED, not hardcoded: a non-0xab key still decrypts.
    for key in (0x3C, 0x5A, 0x01):
        d2 = container([ameba_payload(key)])
        gs2 = ota_findings(d2)
        check(len(gs2) == 1 and gs2[0]["confidence_tier"] == "verified",
              f"derived key 0x{key:02x}: not identified/verified ({gs2})")
        dec2 = extract(d2)
        check(dec2 is not None and dec2[:8] == AMEBA, f"derived key 0x{key:02x}: extract failed")

    # 3a. FP guard: "OTA1" at offset 8 but no valid entry table (garbage) -> not dlink_ota.
    bogus = struct.pack("<II", 0x30190412, 2) + b"OTA1" + os.urandom(44) + os.urandom(2048)
    check(len(ota_findings(bogus)) == 0, "FP guard: bogus entry table must not match dlink_ota")

    # 3b. FP guard: structurally valid container but payload is NOT an Ameba image
    #     -> may be reported (encrypted) but must NOT be decryptable (no descrambled.bin).
    notameba = container([b"NOTAMEBA" + b"\x11" * 504])
    g3 = ota_findings(notameba)
    if g3:
        check(g3[0]["confidence_tier"] != "verified",
              "FP guard: non-Ameba payload must not be reported decryptable")
    check(extract(notameba) is None, "FP guard: non-Ameba payload must not yield descrambled.bin")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: dlink_ota identify + derived-key XOR descramble + FP guards")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Vendor-descramble round-trips: build real encrypted vendor images, then check
moria (a) identifies the scheme at verified tier via the cheap first-block probe
and (b) under -e decrypts byte-identical to the pre-encryption plaintext.

Uses the openssl CLI to produce ciphertext (portable; skips if openssl absent).
Add a scheme = add one builder to CASES. Run: python3 tests/test_deobf.py
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
from shutil import which

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

fails = 0


def check(cond, msg):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {msg}")
    if not cond:
        fails += 1


def aes(work, cipher, key_hex, iv_hex, plain):
    """openssl AES-CBC no-pad encrypt -> ciphertext bytes."""
    pp = os.path.join(work, "p")
    open(pp, "wb").write(plain)
    cp = os.path.join(work, "c")
    r = subprocess.run(["openssl", "enc", cipher, "-nopad", "-K", key_hex, "-iv", iv_hex,
                        "-in", pp, "-out", cp], capture_output=True)
    return open(cp, "rb").read() if r.returncode == 0 else None


def build_shrs(work):
    key, iv = "c05fbf1936c99429ce2a0781f08d6ad8", "000102030405060708090a0b0c0d0e0f"
    plain = (b"\x27\x05\x19\x56" + b"\x00" * 24 + b"deobf".ljust(36, b"\x00"))[:64] + b"KDATA" * 64
    plain += b"\x00" * (-len(plain) % 16)
    ct = aes(work, "-aes-128-cbc", key, iv, plain)
    if ct is None:
        return None
    img = bytearray(0x6DC + len(ct))
    img[0:4] = b"SHRS"
    img[8:12] = struct.pack(">I", len(ct))
    img[0x0C:0x1C] = bytes.fromhex(iv)
    img[0x6DC:] = ct
    return bytes(img), plain, "dlink_shrs"


def build_encrpted_img(work):
    key = bytes([0x68, 0x65, 0x39, 0x2d, 0x34, 0x2b, 0x4d, 0x21, 0x29, 0x64, 0x36, 0x3d, 0x6d, 0x7e,
                 0x77, 0x65, 0x31, 0x2c, 0x71, 0x32, 0x61, 0x33, 0x64, 0x31, 0x6e, 0x26, 0x32, 0x2a,
                 0x5a, 0x5e, 0x25, 0x38]).hex()
    iv = bytes([0x4a, 0x25, 0x31, 0x69, 0x51, 0x6c, 0x38, 0x24, 0x3d, 0x6c, 0x6d, 0x2d, 0x3b, 0x38,
                0x41, 0x45]).hex()
    plain = b"UBI#" + b"\x01" * 60 + b"UBIDATA" * 100
    plain += b"\x00" * (-len(plain) % 16)
    ct = aes(work, "-aes-256-cbc", key, iv, plain)
    if ct is None:
        return None
    return b"encrpted_img" + b"\x00\x00\x00\x00" + ct, plain, "dlink_encrpted_img"


def build_openssl_salted(work):
    # dap1610-family: openssl Salted__ (AES-256, sha256 KDF) of a tar payload.
    plain = bytearray(1024)
    plain[0x101:0x106] = b"ustar"  # tar magic at 0x101
    pp = os.path.join(work, "tar")
    open(pp, "wb").write(bytes(plain))
    cp = os.path.join(work, "salted")
    r = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-md", "sha256", "-salt",
                        "-pass", "pass:2c3b6fa78bd60b41bb0796fef4b058b0", "-in", pp, "-out", cp],
                       capture_output=True)
    if r.returncode != 0:
        return None
    return open(cp, "rb").read(), bytes(plain), "openssl_salted"


def build_mh01(work):
    import os
    devkey = "044b4e59846ecee953662ff2238fcc23"
    salt, iv = os.urandom(8), os.urandom(16)
    plain = b"MH01" + b"\x00" * 12 + b"payload" * 30
    plain += b"\x00" * (-len(plain) % 16)
    pp = os.path.join(work, "pm")
    open(pp, "wb").write(plain)
    cp = os.path.join(work, "cm")
    r = subprocess.run(["openssl", "enc", "-aes-128-cbc", "-md", "sha256", "-pass", "pass:" + devkey,
                        "-S", salt.hex(), "-iv", iv.hex(), "-in", pp, "-out", cp], capture_output=True)
    if r.returncode != 0:
        return None
    salted = b"Salted__" + salt + open(cp, "rb").read()
    h = bytearray(0x41)
    h[0:4] = b"MH01"
    h[0x18:0x1C] = struct.pack("<I", len(salted))
    h[32:64] = iv.hex().encode()
    return bytes(h) + salted, plain, "dlink_mh01"


def build_dlk(work):
    import os
    key = b"044b4e59846ecee953662ff2238fcc23"  # 32 ASCII bytes = AES-256 key
    iv = os.urandom(16)
    plain = b"hsqs" + b"\x00" * 60 + b"squash" * 40
    pp = os.path.join(work, "pd")
    open(pp, "wb").write(plain)
    cp = os.path.join(work, "cd")
    r = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex(),
                        "-in", pp, "-out", cp], capture_output=True)
    if r.returncode != 0:
        return None
    chunk = iv + open(cp, "rb").read()
    total = len(chunk)
    h1 = bytearray(0x50)
    h1[0:3] = b"DLK"
    h1[0x2C:0x30] = struct.pack("<I", 0)
    h2 = bytearray(0x50)
    h2[0:3] = b"DLK"
    h2[0x10:0x14] = struct.pack("<I", total - 0x20)
    h2[0x2C:0x30] = struct.pack("<I", total)
    return bytes(h1) + bytes(h2) + chunk, plain, "dlink_dlk"


def build_tlv(work):
    import hashlib
    import hmac as hmaclib
    model, board = b"TESTMODEL", b"TESTBOARD"
    pw = hmaclib.new(board, model, hashlib.sha1).hexdigest()
    plain = b"hsqs" + b"\x00" * 60 + b"data" * 40
    plain += b"\x00" * (-len(plain) % 16)
    pp = os.path.join(work, "pt")
    open(pp, "wb").write(plain)
    cp = os.path.join(work, "ct2")
    r = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-md", "md5", "-pass", "pass:" + pw,
                        "-salt", "-in", pp, "-out", cp], capture_output=True)
    if r.returncode != 0:
        return None
    t = bytearray(0x74)
    t[0:4] = bytes([0x64, 0x80, 0x19, 0x40])
    t[4:4 + len(model)] = model
    t[0x24:0x24 + len(board)] = board
    return bytes(t) + open(cp, "rb").read(), plain, "dlink_tlv"


def build_engenius(work):
    # EnGenius keyless XOR (no openssl): pattern @0x5C, length @0x20 BE,
    # model_len @0x84 BE, payload from 136+model_len XORed with a fixed key
    # phase-anchored to where it appears in the file (revealed by a zero-run).
    import struct
    key = bytes([0xAC, 0x78, 0x3C, 0x9E, 0xCF, 0x67, 0xB3, 0x59])
    ml = 4
    hdr_end = 136 + ml
    plain = b"hsqs" + bytes(60) + b"\x00" * 8 + bytes(60)
    ref = hdr_end + plain.find(b"\x00" * 8)
    length = hdr_end + len(plain)
    out = bytearray(length)
    out[0x20:0x24] = struct.pack(">I", length)
    out[0x5C:0x63] = bytes.fromhex("12345678") + b"all"
    out[0x84:0x88] = struct.pack(">I", ml)
    for i in range(len(plain)):
        a = hdr_end + i
        out[a] = plain[i] ^ key[(a - ref) % 8]
    return bytes(out), plain, "engenius"


CASES = [("SHRS", build_shrs), ("encrpted_img", build_encrpted_img),
         ("openssl_salted", build_openssl_salted), ("MH01", build_mh01),
         ("DLK", build_dlk), ("TLV", build_tlv), ("engenius", build_engenius)]


def main():
    if not os.path.exists(MORIA):
        print(f"error: {MORIA} not built", file=sys.stderr)
        return 2
    if not which("openssl"):
        print("SKIP [deobf]: openssl not installed")
        return 0
    print("test_deobf: vendor-descramble round-trips")

    with tempfile.TemporaryDirectory() as d:
        for label, builder in CASES:
            built = builder(d)
            if built is None:
                print(f"SKIP [deobf/{label}]: openssl enc failed")
                continue
            img_bytes, plain, scheme = built
            img = os.path.join(d, f"{label}.bin")
            open(img, "wb").write(img_bytes)

            r = subprocess.run([MORIA, "-j", img], capture_output=True)
            f = json.loads(r.stdout)["findings"][0]
            check(f["type"] == scheme, f"[{label}] identified as {scheme} (got {f['type']})")
            check(f["confidence_tier"] == "verified",
                  f"[{label}] verified via probe (got {f['confidence_tier']})")

            outdir = os.path.join(d, f"{label}.out")
            subprocess.run([MORIA, "-e", "-C", outdir, img], capture_output=True)
            man = json.loads(open(os.path.join(outdir, "manifest.json")).read())
            entry = man["extracted"][0]
            check(entry["status"] == "ok", f"[{label}] descramble ok (got {entry['status']})")
            blob = os.path.join(outdir, entry["root"], "descrambled.bin")
            got = open(blob, "rb").read() if os.path.exists(blob) else b""
            check(got == plain, f"[{label}] descrambled.bin byte-identical to plaintext")

    print("PASS" if fails == 0 else f"FAIL ({fails})")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

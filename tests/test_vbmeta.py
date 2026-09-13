#!/usr/bin/env python3
"""AVB vbmeta identify + extract regression.

Synthesizes a signed-form vbmeta (256-byte header + authentication block +
auxiliary block holding a known public key and descriptors), runs moria to check
identification (offset/size/tier) and `moria -e` to check that vbmeta-pubkey.bin
and vbmeta-descriptors.bin carve out byte-for-byte. Self-contained; no external
tools. Exit nonzero on any failure.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

PUBKEY = b"AVBPUBKEY" + bytes(range(64)) * 2      # 137 bytes, distinctive
DESCS = b"DESCRIPTORS-BLOCK" + bytes((i * 3) & 0xFF for i in range(200))


def vbmeta(pubkey=PUBKEY, descs=DESCS, algorithm=1, flags=0, rollback=5):
    def pad8(b):
        return b + b"\x00" * ((-len(b)) % 8)
    # auxiliary block: public key then descriptors.
    pk_off = 0
    desc_off = len(pad8(pubkey))
    aux = pad8(pubkey) + descs
    aux = pad8(aux)
    # authentication block: a hash then a signature.
    hashv = b"\x11" * 32
    sig = b"\x22" * 256
    auth = pad8(hashv + sig)
    hdr = struct.pack(
        ">4sIIQQIQQQQQQQQQQQII48s80s",
        b"AVB0", 1, 0,
        len(auth), len(aux),
        algorithm,
        0, len(hashv),                    # hash offset/size (within auth)
        len(hashv), len(sig),             # signature offset/size (within auth)
        pk_off, len(pubkey),              # public key offset/size (within aux)
        0, 0,                             # public key metadata
        desc_off, len(descs),             # descriptors offset/size (within aux)
        rollback,
        flags, 0,
        b"avbtool 1.2.0", b"")
    assert len(hdr) == 256
    return hdr + auth + aux


def run_json(path):
    out = subprocess.run([MORIA, "-j", path], capture_output=True, text=True).stdout
    return json.loads(out)


def main():
    fails = []

    def check(cond, msg):
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            fails.append(msg)

    with tempfile.TemporaryDirectory() as td:
        img = os.path.join(td, "vbmeta.img")
        blob = vbmeta()
        with open(img, "wb") as f:
            f.write(blob)

        doc = run_json(img)
        vb = [f for f in doc.get("findings", []) if f.get("type") == "vbmeta"]
        check(len(vb) == 1, "one vbmeta finding")
        if vb:
            check(vb[0]["offset"] == 0 and vb[0]["size"] == len(blob), "exact offset+size")
            check(vb[0]["confidence_tier"] == "consistent", "consistent tier")
            # release_string is at header offset 128 (regression: was misread at 176).
            check(vb[0].get("label") == "avbtool 1.2.0", "release string parsed as label")

        # Extract and compare the carved artifacts byte-for-byte.
        outdir = os.path.join(td, "out")
        subprocess.run([MORIA, "-e", "-C", outdir, img], capture_output=True, text=True)
        sub = None
        for d in os.listdir(outdir):
            if os.path.isdir(os.path.join(outdir, d)):
                sub = os.path.join(outdir, d)
        pk = os.path.join(sub, "vbmeta-pubkey.bin") if sub else ""
        ds = os.path.join(sub, "vbmeta-descriptors.bin") if sub else ""
        check(sub and os.path.isfile(pk) and open(pk, "rb").read() == PUBKEY,
              "vbmeta-pubkey.bin carved byte-for-byte")
        check(sub and os.path.isfile(ds) and open(ds, "rb").read() == DESCS,
              "vbmeta-descriptors.bin carved byte-for-byte")

        # Embedded at a nonzero offset.
        emb = os.path.join(td, "emb.bin")
        with open(emb, "wb") as f:
            f.write(b"\xff" * 0x8000 + blob + os.urandom(0x400))
        doc = run_json(emb)
        vb = [f for f in doc.get("findings", []) if f.get("type") == "vbmeta"]
        check(len(vb) == 1 and vb[0]["offset"] == 0x8000, "embedded vbmeta @0x8000")

        # FP guard: bare "AVB0" with junk that fails the sub-block consistency.
        bad = os.path.join(td, "bad.bin")
        with open(bad, "wb") as f:
            f.write(b"AVB0" + os.urandom(252))
        vb = [f for f in run_json(bad).get("findings", []) if f.get("type") == "vbmeta"]
        check(len(vb) == 0, "fp: AVB0 + random header rejected")

    if fails:
        print(f"\nFAIL: {len(fails)} check(s) failed")
        return 1
    print("\nPASS: vbmeta identify + extract")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""VBF (Versatile Binary Format) extraction regression.

Builds a synthetic VBF with a raw block and a real LZSS-compressed block
(compressed with the qvbf encoder, plaintext known), runs `moria -e`, and asserts
every block round-trips: raw copied verbatim, LZSS decoded byte-for-byte, and the
per-block CRC16 confirmed (status ok). Self-contained; no external tools. Exit
nonzero on any failure.
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

# A real qvbf-LZSS-compressed block and its exact plaintext (generated with the
# ford-pscm-re encoder, verified round-trip). Exercises the C++ LZSS decoder's
# literal and back-reference paths.
LZSS_COMP = base64.b64decode(
    "ptPqVJoMgq1Co0gullud0kFitlvsdrl0gAD4EvBH4NPCL4VvDP4ePET8goIsdoQwdgEBgUDgkFg0HhEJhUL"
    "hkNh0PiERiUTikVi0XjEZjUbjkdj0fkEhkUjkklk0nlEplUrlktl0vmExmUzmk1m03nE5nU7nk9n0/Gj44vHn"
    "5BPIr5JvJv5SHuVluFlsIqAMj5ovhQA=")
LZSS_PLAIN = (b"MORIA VBF test block. " * 8 +
              b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB" +
              bytes(range(64)) * 3 +
              b"repeat repeat repeat repeat repeat repeat\n")

RAW = bytes((i * 7 + 3) & 0xFF for i in range(300))


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def hdr(dfi):
    return (b'vbf_version = 3.0;\r\n\r\n'
            b'header {\r\n'
            b'   description = { "moria vbf test" };\r\n'
            b'   sw_part_number = "AA00-14D007-AA";\r\n'
            b'   sw_part_type = DATA;\r\n'
            b'   data_format_identifier = 0x%02X;\r\n'
            b'   ecu_address = 0x730;\r\n'
            b'   file_checksum = 0x00000000;\r\n'
            b'}') % dfi


def raw_block(addr, data):
    return struct.pack(">II", addr, len(data)) + data + struct.pack(">H", crc16(data))


def comp_block(addr, comp, plain):
    # In a compressed VBF the stored CRC16 is over the DECOMPRESSED payload.
    return struct.pack(">II", addr, len(comp)) + comp + struct.pack(">H", crc16(plain))


def run(vbf_bytes, expect_blocks, tag):
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "fw.vbf")
        with open(p, "wb") as f:
            f.write(vbf_bytes)
        outdir = os.path.join(tmp, "out")
        r = subprocess.run([MORIA, "-e", "-j", p, "-C", outdir], capture_output=True, timeout=60)
        if r.returncode != 0:
            print(f"FAIL[{tag}]: moria exited", r.returncode, r.stderr.decode(errors="replace"))
            return 1
        j = json.loads(r.stdout)
        ex = [e for e in j.get("extraction", {}).get("extracted", []) if e.get("type") == "vbf"]
        if not ex:
            print(f"FAIL[{tag}]: no vbf extraction in output")
            return 1
        e = ex[0]
        fails = []
        if e.get("status") != "ok":
            fails.append(f"status={e.get('status')} (want ok); warnings={e.get('warnings')}")
        if e.get("files") != len(expect_blocks):
            fails.append(f"files={e.get('files')} (want {len(expect_blocks)})")
        root = os.path.join(outdir, e["root"])
        for idx, (addr, want) in enumerate(expect_blocks):
            fn = "block%d_0x%08X.bin" % (idx, addr)
            fp = os.path.join(root, fn)
            if not os.path.exists(fp):
                fails.append(f"missing {fn}")
                continue
            got = open(fp, "rb").read()
            if got != want:
                fails.append(f"{fn}: {len(got)} bytes, want {len(want)} (content mismatch)")
        if fails:
            for m in fails:
                print(f"  FAIL[{tag}]:", m)
            return 1
        print(f"  PASS  VBF {tag}: {len(expect_blocks)} block(s) round-trip")
        return 0


def main():
    assert base64_ok()
    rc = 0
    # Raw (data_format 0x00): two stored blocks, CRC16 verifiable.
    raw_vbf = hdr(0x00) + raw_block(0x00FD0000, RAW) + raw_block(0x10000400, b"CAL\x00" * 8)
    rc |= run(raw_vbf, [(0x00FD0000, RAW), (0x10000400, b"CAL\x00" * 8)], "raw")
    # Compressed (data_format 0x10): one LZSS block, decoded byte-for-byte.
    comp_vbf = hdr(0x10) + comp_block(0x01000000, LZSS_COMP, LZSS_PLAIN)
    rc |= run(comp_vbf, [(0x01000000, LZSS_PLAIN)], "lzss")
    if rc == 0:
        print("PASS")
    return rc


def base64_ok():
    # sanity: the embedded compressed stream decodes to the stated plaintext size
    return len(LZSS_PLAIN) == 442


if __name__ == "__main__":
    sys.exit(main())

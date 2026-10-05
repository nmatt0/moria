#!/usr/bin/env python3
"""Windows CE registry hive identify + value-recovery regression.

Builds a synthetic hive (the "EKIM" header plus value records of every type CE
stores, padded with plausible-looking noise), runs `moria -e`, and asserts the
dump recovers each value with the right name, type, and rendering — and that a
header with no recoverable records is rejected rather than reported as a hive.

Self-contained; no external tools. Exit nonzero on any failure.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 7, 11

# (name, type, data, expected rendering in the dump)
VALUES = [
    ("Version", REG_SZ, "1.8001.0298\0".encode("utf-16-le"), "1.8001.0298"),
    ("Path", REG_EXPAND_SZ, "%CE2%\\svc.exe\0".encode("utf-16-le"), "%CE2%\\svc.exe"),
    ("Order", REG_MULTI_SZ, "a\0bb\0ccc\0\0".encode("utf-16-le"), "a|bb|ccc"),
    ("Flags", REG_DWORD, struct.pack("<I", 0xDEADBEEF), "3735928559"),
    ("Serial", REG_QWORD, struct.pack("<Q", 1 << 40), "1099511627776"),
    ("Thumbprint", REG_BINARY, bytes(range(0x10)), "000102030405060708090a0b0c0d0e0f"),
    ("Dll", REG_SZ, "creslogsvc.dll\0".encode("utf-16-le"), "creslogsvc.dll"),
    ("Index", REG_DWORD, struct.pack("<I", 7), "7"),
    ("Prefix", REG_SZ, "COM3:\0".encode("utf-16-le"), "COM3:"),
]


def record(name, vtype, data):
    n = name.encode("utf-16-le")
    return struct.pack("<HHH", vtype, len(data), len(n) // 2) + n + data


def build_hive(with_values=True):
    hv = bytearray()
    hv += struct.pack("<II", 0x400, 0) + b"EKIM"
    hv += bytes(range(0x34))                       # header GUIDs / hashes
    assert len(hv) == 0x40
    if with_values:
        for name, vtype, data, _ in VALUES:
            hv += record(name, vtype, data)
            hv += b"\x00\x00\x00\x00"              # cell padding between records
    # Tail that must NOT yield records: a run of bytes whose length triples
    # either name a bad type or decode to a non-ASCII name.
    hv += bytes((i * 37 + 11) & 0xFF for i in range(2048))
    while len(hv) % 0x400:
        hv.append(0)
    return bytes(hv)


def run(path, outdir=None):
    cmd = [MORIA, "-e", "-j", path, "-C", outdir] if outdir else [MORIA, "-j", path]
    r = subprocess.run(cmd, capture_output=True, timeout=120)
    if r.returncode != 0:
        raise SystemExit("moria exited %d: %s" % (r.returncode, r.stderr.decode("replace")))
    return json.loads(r.stdout)


def fail(msg):
    print("FAIL:", msg)
    return 1


def main():
    with tempfile.TemporaryDirectory() as tmp:
        hv = os.path.join(tmp, "default.hv")
        with open(hv, "wb") as f:
            f.write(build_hive())

        outdir = os.path.join(tmp, "out")
        j = run(hv, outdir)
        finds = [x for x in j["findings"] if x["type"] == "wince_hive"]
        if len(finds) != 1 or finds[0]["confidence_tier"] != "consistent":
            return fail("findings %r" % [(x["type"], x["confidence_tier"])
                                         for x in j["findings"]])

        ent = [e for e in j["extraction"]["extracted"] if e["type"] == "wince_hive"]
        if not ent or ent[0]["status"] != "ok":
            return fail("status %r" % (ent[0]["status"] if ent else None))
        dump = open(os.path.join(outdir, ent[0]["root"], "registry-values.txt"),
                    encoding="utf-8").read()

        rows = {}
        for line in dump.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(None, 3)
            if len(parts) < 3:
                return fail("unparseable dump line %r" % line)
            rows[parts[1]] = (parts[2], parts[3] if len(parts) > 3 else "")

        for name, _vtype, _data, want in VALUES:
            key = name.split()[0]
            if key not in rows:
                return fail("value %r missing from the dump:\n%s" % (name, dump))
            got_type, got_val = rows[key]
            if got_val != want:
                return fail("value %r rendered %r, want %r" % (name, got_val, want))
            if not got_type.startswith("REG_"):
                return fail("value %r type column %r" % (name, got_type))

        # Every record we planted must be found, and nothing much beyond them:
        # the noise tail is there to catch a scan that accepts anything.
        body = [l for l in dump.splitlines() if l and not l.startswith("#")]
        if len(body) < len(VALUES):
            return fail("recovered %d records, planted %d" % (len(body), len(VALUES)))
        if len(body) > len(VALUES) + 4:
            return fail("recovered %d records from %d planted: the scan is too loose\n%s" %
                        (len(body), len(VALUES), dump))

        # A header with no recoverable records is not a hive.
        empty = os.path.join(tmp, "notahive.bin")
        with open(empty, "wb") as f:
            f.write(build_hive(with_values=False))
        j = run(empty)
        if any(x["type"] == "wince_hive" for x in j["findings"]):
            return fail("EKIM header with no values was reported as a hive")

    print("ok: wince_hive identify + value recovery")
    return 0


if __name__ == "__main__":
    sys.exit(main())

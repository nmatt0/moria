#!/usr/bin/env python3
"""Deterministic regression test: build synthetic samples, run moria, assert
each is identified as the expected type at or above the expected confidence.
Negatives (type None) must produce no finding of a known firmware/format type.

Exit status is nonzero on any failure. No external corpus required.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_samples  # noqa: E402

BIN = os.path.join(HERE, "..", "build", "moria")


def run(path):
    r = subprocess.run([BIN, "-j", path], capture_output=True, timeout=60)
    return json.loads(r.stdout)


def coverage_gate():
    """Every core signature (signatures/*.toml) must have a synthetic fixture,
    else be explicitly waived. Keeps the suite honest as signatures grow."""
    import glob
    import re
    waived = set()  # none currently — all core sigs have fixtures
    sig_names = set()
    for p in glob.glob(os.path.join(HERE, "..", "signatures", "*.toml")):
        m = re.search(r'(?m)^name\s*=\s*"([^"]+)"', open(p).read())
        if m:
            sig_names.add(m.group(1))
    covered = {t for _, _, t, _ in gen_samples.MANIFEST if t}
    missing = sig_names - covered - waived
    if missing:
        print(f"  COVERAGE GAP: core signatures with no fixture: {sorted(missing)}")
    return not missing


def sig_load_sanity():
    """All signature sets (core + firmware + generated via --broad) must load
    with zero warnings — a malformed .toml otherwise only surfaces at runtime."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".txt") as tf:
        tf.write(b"hello\n")
        tf.flush()
        r = subprocess.run([BIN, "-j", "--broad", tf.name], capture_output=True, timeout=60)
    warns = [ln for ln in r.stderr.decode(errors="replace").splitlines() if "warning" in ln.lower()]
    if warns:
        print(f"  SIGNATURE LOAD WARNINGS ({len(warns)}):")
        for w in warns[:5]:
            print(f"    {w}")
    return not warns


def list_members_check():
    """--list must enumerate real tar/zip members (names+sizes) without extracting."""
    import tarfile
    import tempfile
    import zipfile
    ok = True
    with tempfile.TemporaryDirectory() as d:
        # tar
        tp = os.path.join(d, "a.tar")
        with tarfile.open(tp, "w") as t:
            for name, data in [("etc/passwd", b"root:x:0:0\n"), ("bin/sh", b"\x7fELFxx")]:
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                import io
                t.addfile(ti, io.BytesIO(data))
        r = subprocess.run([BIN, "-j", "--list", tp], capture_output=True, timeout=30)
        fs = json.loads(r.stdout)["findings"]
        names = {m["name"] for f in fs if f["type"] == "tar" for m in f.get("members", [])}
        if not {"etc/passwd", "bin/sh"} <= names:
            print(f"  LIST tar: expected members missing, got {names}")
            ok = False
        # zip
        zp = os.path.join(d, "a.zip")
        with zipfile.ZipFile(zp, "w") as z:
            z.writestr("config.xml", b"<x/>")
            z.writestr("lib/app.so", b"\x7fELF")
        r = subprocess.run([BIN, "-j", "--list", zp], capture_output=True, timeout=30)
        fs = json.loads(r.stdout)["findings"]
        names = {m["name"] for f in fs if f["type"] == "zip" for m in f.get("members", [])}
        if not {"config.xml", "lib/app.so"} <= names:
            print(f"  LIST zip: expected members missing, got {names}")
            ok = False
    return ok


def elf_size_sanity():
    """A bogus section header table (index 0 not SHT_NULL) must not inflate the
    reported ELF size. Regression for elf_size trusting garbage section offsets,
    which let an ELF embedded in a yaffs2 image (interleaved with OOB bytes)
    claim gigabytes and mask every region behind it."""
    import struct
    import tempfile
    FILE_SZ = 0x10000
    b = bytearray(FILE_SZ)
    b[0:4] = b"\x7fELF"
    b[4] = 1  # ELFCLASS32
    b[5] = 1  # ELFDATA2LSB
    b[6] = 1  # version
    struct.pack_into("<H", b, 16, 2)       # e_type = EXEC
    struct.pack_into("<H", b, 18, 40)      # e_machine = ARM
    struct.pack_into("<I", b, 20, 1)       # e_version
    struct.pack_into("<I", b, 28, 0x34)    # e_phoff
    struct.pack_into("<I", b, 32, 0x2000)  # e_shoff
    struct.pack_into("<H", b, 40, 52)      # e_ehsize
    struct.pack_into("<H", b, 42, 32)      # e_phentsize
    struct.pack_into("<H", b, 44, 1)       # e_phnum
    struct.pack_into("<H", b, 46, 40)      # e_shentsize
    struct.pack_into("<H", b, 48, 3)       # e_shnum
    # One PT_LOAD program header: the real on-disk reach is ~4 KiB.
    struct.pack_into("<I", b, 0x34 + 0, 1)        # p_type = PT_LOAD
    struct.pack_into("<I", b, 0x34 + 4, 0)        # p_offset
    struct.pack_into("<I", b, 0x34 + 16, 0x1000)  # p_filesz
    # Section table @0x2000: index 0 is NOT the mandatory null entry, and index 1
    # claims a large in-bounds extent. Both must be ignored.
    struct.pack_into("<I", b, 0x2000 + 0, 1)       # sh[0].sh_name != 0 -> not SHT_NULL
    struct.pack_into("<I", b, 0x2000 + 4, 1)       # sh[0].sh_type = PROGBITS
    struct.pack_into("<I", b, 0x2000 + 40 + 4, 1)      # sh[1].sh_type = PROGBITS
    struct.pack_into("<I", b, 0x2000 + 40 + 16, 0x100)   # sh[1].sh_offset
    struct.pack_into("<I", b, 0x2000 + 40 + 20, 0xD000)  # sh[1].sh_size -> end 0xD100
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "bogus_sections.elf")
        with open(p, "wb") as f:
            f.write(b)
        fs = run(p)["findings"]
    elf = [f for f in fs if f["type"] == "elf" and f["offset"] == 0]
    if not elf:
        print(f"  ELF-SIZE: no elf finding (got {[f['type'] for f in fs]})")
        return False
    sz = elf[0]["size"]
    if sz > 0x2000:  # must reflect the ~4 KiB program image, not the 52 KiB garbage
        print(f"  ELF-SIZE: bogus section table inflated size to {sz:#x} (want <= 0x2000)")
        return False
    return True


def main():
    if not os.path.exists(BIN):
        print(f"error: {BIN} not built", file=sys.stderr)
        return 2

    fails = []
    with tempfile.TemporaryDirectory() as d:
        for name, builder, expect_type, min_conf in gen_samples.MANIFEST:
            path = os.path.join(d, name)
            with open(path, "wb") as f:
                f.write(builder())
            doc = run(path)
            findings = doc["findings"]
            if expect_type is None:
                # Negative: no finding should claim a real format for this blob.
                got = [f["type"] for f in findings]
                status = "ok" if not got else f"UNEXPECTED {got}"
                if got:
                    fails.append((name, status))
            else:
                match = [f for f in findings if f["type"] == expect_type]
                if not match:
                    status = f"MISSING {expect_type} (got {[f['type'] for f in findings]})"
                    fails.append((name, status))
                elif max(f["confidence"] for f in match) < min_conf:
                    c = max(f["confidence"] for f in match)
                    status = f"LOW CONF {c} < {min_conf}"
                    fails.append((name, status))
                else:
                    status = f"ok ({expect_type} @ {max(f['confidence'] for f in match)})"
            print(f"  {'FAIL' if (name in [x[0] for x in fails]) else 'PASS'}  {name:22} {status}")

    print("-" * 60)
    cov_ok = coverage_gate()
    load_ok = sig_load_sanity()
    list_ok = list_members_check()
    elf_ok = elf_size_sanity()
    if fails or not cov_ok or not load_ok or not list_ok or not elf_ok:
        extra = []
        if not cov_ok:
            extra.append("coverage gap")
        if not load_ok:
            extra.append("sig-load warnings")
        if not list_ok:
            extra.append("--list broken")
        if not elf_ok:
            extra.append("elf-size regression")
        print(f"FAIL: {len(fails)}/{len(gen_samples.MANIFEST)} samples"
              f"{(' + ' + ', '.join(extra)) if extra else ''}")
        return 1
    print(f"PASS: all {len(gen_samples.MANIFEST)} samples; every core signature has a fixture; "
          f"all signature sets load clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""NILFS2 extraction regression (issue #64).

NILFS2 is log-structured: the live tree is reached through the latest
checkpoint. Layers:

  1. Real empty image (always-on if mkfs.nilfs2 is present, no privilege):
     mkfs.nilfs2 builds an empty filesystem; moria must identify and extract it
     cleanly (just the root directory). This exercises the whole metadata chain
     against genuine bytes: superblock selection, super root, DAT translation,
     cpfile checkpoint lookup, ifile inode read, root-directory walk.
  2. Real populated round-trip (self-skips unless the image can be mounted, i.e.
     the nilfs2 module is loaded and the test runs with mount privilege): build a
     known tree, mount + copy it in, extract with moria, compare byte-for-byte.
     This is the only layer that exercises file content (direct + B-tree block
     maps, holes) and symlinks, so it is the primary correctness check where it
     can run. mkfs.nilfs2 has no populate-from-directory mode and the kernel
     driver is required to write, so an unprivileged populate is not possible.
  3. Corruption robustness: mangled superblock/metadata must never crash and must
     report a sane status (the ASan build is the out-of-bounds oracle).

Run: python3 tests/test_nilfs2_extract.py [path/to/moria]
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")


def tree_manifest(root):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames) + list(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                out[rel] = ("link", os.readlink(full))
            elif os.path.isdir(full):
                out[rel] = ("dir",)
            else:
                with open(full, "rb") as f:
                    out[rel] = ("file", hashlib.sha256(f.read()).hexdigest())
    return out


# mkfs.nilfs2 needs >= 2 MiB. Keep images small: a corrupt superblock fails the
# CRC check, so moria falls back to a full broad scan whose cost scales with the
# image size (and is heavily amplified under ASan), so corruption cases in
# particular must stay small to run quickly.
def mkfs_empty(path, size_mb=4):
    with open(path, "wb") as f:
        f.truncate(size_mb << 20)
    r = subprocess.run(["mkfs.nilfs2", "-q", "-B", "16", path], capture_output=True)
    return r.returncode == 0


def extract(outdir, img):
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    if r.returncode != 0:
        return None, r
    try:
        return json.loads(r.stdout.decode())["extraction"]["extracted"][0], r
    except Exception:
        return None, r


def test_real_empty(work):
    if not shutil.which("mkfs.nilfs2"):
        print("SKIP [empty]: mkfs.nilfs2 (nilfs-utils) not installed")
        return 0
    img = os.path.join(work, "empty.img")
    if not mkfs_empty(img):
        print("SKIP [empty]: mkfs.nilfs2 failed")
        return 0
    outdir = os.path.join(work, "empty.out")
    entry, r = extract(outdir, img)
    if entry is None:
        print(f"FAIL [empty]: not identified/extracted\n{r.stdout[:200]}")
        return 1
    if entry["type"] == "nilfs2" and entry["status"] == "ok" and entry["files"] == 0:
        print("PASS [empty]: empty image identified + extracted clean (status ok)")
        return 0
    print(f"FAIL [empty]: type={entry['type']} status={entry['status']} files={entry['files']}")
    return 1


def build_tree(src):
    os.makedirs(os.path.join(src, "etc"))
    os.makedirs(os.path.join(src, "usr", "bin"))
    os.makedirs(os.path.join(src, "empty"))
    with open(os.path.join(src, "etc", "hostname"), "wb") as f:
        f.write(b"nilfs2-roundtrip\n")
    with open(os.path.join(src, "etc", "zeros.dat"), "wb") as f:
        f.write(b"\x00" * (300 * 1024))          # multi-block, holes-friendly
    with open(os.path.join(src, "usr", "bin", "rand.bin"), "wb") as f:
        f.write(os.urandom(400 * 1024))          # B-tree block map
    with open(os.path.join(src, "small.txt"), "wb") as f:
        f.write(b"tiny\n")                         # direct block map
    p = os.path.join(src, "usr", "bin", "run.sh")
    with open(p, "wb") as f:
        f.write(b"#!/bin/sh\necho hi\n")
    os.chmod(p, 0o755)
    os.symlink("hostname", os.path.join(src, "etc", "hn.lnk"))
    os.symlink("../etc/hostname", os.path.join(src, "usr", "bin", "hn2.lnk"))


def test_roundtrip(work):
    """Needs mkfs.nilfs2 + the ability to mount (module + privilege)."""
    if not shutil.which("mkfs.nilfs2") or not shutil.which("mount"):
        print("SKIP [roundtrip]: mkfs.nilfs2 / mount not available")
        return 0
    img = os.path.join(work, "rt.img")
    src = os.path.join(work, "rt.src")
    mnt = os.path.join(work, "rt.mnt")
    os.makedirs(mnt)
    build_tree(src)
    if not mkfs_empty(img, size_mb=32):  # room for ~700 KiB of files + nilfs overhead
        print("SKIP [roundtrip]: mkfs.nilfs2 failed")
        return 0
    m = subprocess.run(["mount", "-t", "nilfs2", "-o", "loop", img, mnt], capture_output=True)
    if m.returncode != 0:
        print("SKIP [roundtrip]: cannot mount nilfs2 (needs module + privilege)")
        return 0
    try:
        subprocess.run(["cp", "-a", src + "/.", mnt + "/"], check=False)
        subprocess.run(["sync"])
    finally:
        subprocess.run(["umount", mnt], capture_output=True)
    expected = tree_manifest(src)
    outdir = os.path.join(work, "rt.out")
    entry, r = extract(outdir, img)
    if entry is None:
        print(f"FAIL [roundtrip]: no manifest\n{r.stdout[:200]}")
        return 1
    if entry["status"] not in ("ok", "partial"):
        print(f"FAIL [roundtrip]: status={entry['status']}")
        return 1
    got = tree_manifest(os.path.join(outdir, entry["root"]))
    if got == expected:
        print(f"PASS [roundtrip]: {entry['files']} files, {entry['dirs']} dirs, "
              f"{entry['symlinks']} symlinks, round-trips byte-for-byte")
        return 0
    only_exp = set(expected) - set(got)
    only_got = set(got) - set(expected)
    mism = {k for k in expected.keys() & got.keys() if expected[k] != got[k]}
    print(f"FAIL [roundtrip]: missing={sorted(only_exp)} extra={sorted(only_got)} "
          f"mismatched={sorted(mism)}")
    return 1


def test_corruption(work):
    if not shutil.which("mkfs.nilfs2"):
        print("SKIP [corrupt]: mkfs.nilfs2 not installed")
        return 0
    img = os.path.join(work, "corrupt.img")
    if not mkfs_empty(img):
        print("SKIP [corrupt]: mkfs.nilfs2 failed")
        return 0
    base = bytearray(open(img, "rb").read())
    cases = {}
    t = bytearray(base); t = t[: len(t) // 3]; cases["truncated"] = t          # cut the device
    z = bytearray(base)
    z[1024 + 0x40: 1024 + 0x48] = (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")    # bad last_pseg
    cases["bad-last-pseg"] = z
    g = bytearray(base)
    for i in range(0x10000, 0x10000 + 0x8000):                                   # garble early blocks
        g[i] = (i * 29) & 0xFF
    cases["garbled-tree"] = g
    failures = 0
    for label, data in cases.items():
        p = os.path.join(work, f"c_{label}.img")
        with open(p, "wb") as f:
            f.write(bytes(data))
        outdir = os.path.join(work, f"c_{label}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, p],
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            print(f"FAIL [corrupt {label}]: moria exit {r.returncode} (crash/sanitizer?)\n"
                  f"{r.stderr.decode()[-600:]}")
            failures += 1
            continue
        try:
            e = json.loads(r.stdout.decode()).get("extraction", {}).get("extracted", [{}])[0]
            status = e.get("status", "")
        except Exception:
            status = ""
        ok = status in ("", "ok", "partial") or status.startswith("error:")
        print(f"{'PASS' if ok else 'FAIL'} [corrupt {label}]: no crash, status={status!r}")
        failures += 0 if ok else 1
    return failures


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as work:
        failures = 0
        failures += test_real_empty(work)
        failures += test_roundtrip(work)
        failures += test_corruption(work)
    if failures:
        print(f"\n{failures} nilfs2 extraction check(s) failed")
        return 1
    print("\nall nilfs2 extraction checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

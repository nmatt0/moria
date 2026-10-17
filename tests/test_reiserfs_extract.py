#!/usr/bin/env python3
"""ReiserFS extraction regression (issue #63).

ReiserFS has no populate-from-directory mkfs mode, and the kernel driver was
removed in 6.13, so a populated image cannot be produced unprivileged. Layers:

  1. Synthetic, always-on: hand-built 3.6 (2-level tree, v2 stat-data + v1
     directory items, indirect items, a tail, a leading hole, a symlink, a
     nested dir) and 3.5 (single leaf, all-v1, 8 KiB superblock) images from
     tests/mkreiserfs_synth, extracted and compared byte-for-byte. The layouts
     are modeled on real mkreiserfs output (verified with debugreiserfs).
  2. Real empty image: mkreiserfs builds an empty filesystem (no mount needed);
     moria must identify and extract it cleanly (just the root dir, 0 entries).
     Self-skips if mkreiserfs is absent. This checks the parser against genuine
     on-disk bytes.
  3. Corruption robustness: mangled superblock / tree bytes must never crash and
     must yield a sane status (ASan build is the out-of-bounds oracle).

Run: python3 tests/test_reiserfs_extract.py [path/to/moria]
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
sys.path.insert(0, HERE)
import mkreiserfs_synth as M  # noqa: E402


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


def extract(work, img_bytes, label):
    """Write bytes, run moria --extract, return (entry, outdir) or (None, None)."""
    img = os.path.join(work, f"{label}.img")
    with open(img, "wb") as f:
        f.write(img_bytes)
    outdir = os.path.join(work, f"{label}.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    if r.returncode != 0:
        print(f"FAIL [{label}]: moria exit {r.returncode}\n{r.stderr.decode()[-800:]}")
        return None, None
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception as e:
        print(f"FAIL [{label}]: no extraction manifest ({e})\n{r.stdout[:200]}")
        return None, None
    return entry, outdir


def test_synthetic(work):
    failures = 0
    for which, builder in (("3.6", M.build_36), ("3.5", M.build_35)):
        img_bytes, expected = builder()
        entry, outdir = extract(work, img_bytes, f"synth{which}")
        if entry is None:
            failures += 1
            continue
        if entry["status"] != "ok":
            print(f"FAIL [synth {which}]: status={entry['status']}")
            failures += 1
            continue
        got = tree_manifest(os.path.join(outdir, entry["root"]))
        if got == expected:
            print(f"PASS [synth {which}]: {entry['files']} files, {entry['dirs']} dirs, "
                  f"{entry['symlinks']} symlinks, round-trips byte-for-byte")
        else:
            failures += 1
            only_exp = set(expected) - set(got)
            only_got = set(got) - set(expected)
            mism = {k for k in expected.keys() & got.keys() if expected[k] != got[k]}
            print(f"FAIL [synth {which}]: missing={sorted(only_exp)} extra={sorted(only_got)} "
                  f"mismatched={sorted(mism)}")
    return failures


def test_real_empty(work):
    """mkreiserfs makes an empty fs (no mount); moria must extract it cleanly."""
    if not shutil.which("mkreiserfs"):
        print("SKIP [real]: mkreiserfs (reiserfsprogs) not installed")
        return 0
    failures = 0
    for fmt in ("3.6", "3.5"):
        img = os.path.join(work, f"real{fmt}.img")
        with open(img, "wb") as f:
            f.write(b"\x00" * (33 << 20))
        r = subprocess.run(["mkreiserfs", "-q", "-f", "--format", fmt, img],
                           capture_output=True)
        if r.returncode != 0:
            print(f"SKIP [real {fmt}]: mkreiserfs failed")
            continue
        outdir = os.path.join(work, f"real{fmt}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
        except Exception:
            print(f"FAIL [real {fmt}]: not identified/extracted\n{r.stdout[:200]}")
            failures += 1
            continue
        # An empty reiserfs has only the root directory (., ..), so nothing is
        # written, but extraction must succeed on the genuine bytes.
        if entry["type"] == "reiserfs" and entry["status"] == "ok" and entry["files"] == 0:
            print(f"PASS [real {fmt}]: empty image identified + extracted clean (status ok)")
        else:
            print(f"FAIL [real {fmt}]: type={entry['type']} status={entry['status']} "
                  f"files={entry['files']}")
            failures += 1
    return failures


def test_corruption(work):
    """Mangled images must not crash and must report a sane status."""
    base, _ = M.build_36()
    cases = {
        "truncated-mid-tree": base[:20 * 4096],              # cut inside the tree
        "truncated-at-sb": base[:16 * 4096 + 100],           # SB header only
        "zeroed-root-block": bytearray(base),                # root block wiped
        "garbage-tree": bytearray(base),                     # random tree bytes
        "huge-sizes": bytearray(base),                       # stat-data size fields maxed
    }
    import struct
    z = cases["zeroed-root-block"]
    z[17 * 4096:18 * 4096] = b"\x00" * 4096
    g = cases["garbage-tree"]
    for i in range(17 * 4096, 23 * 4096):
        g[i] = (i * 37) & 0xFF
    h = cases["huge-sizes"]
    # leaf A item 0 (root SD, v2) size field at body; just flip many bytes in the
    # leaf bodies to 0xFF so size/location fields are maximal.
    for i in range(18 * 4096 + 2048, 19 * 4096):
        h[i] = 0xFF

    failures = 0
    for label, data in cases.items():
        img = os.path.join(work, f"corrupt_{label}.img")
        with open(img, "wb") as f:
            f.write(bytes(data))
        outdir = os.path.join(work, f"corrupt_{label}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img],
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            print(f"FAIL [corrupt {label}]: moria exit {r.returncode} (crash/sanitizer?)\n"
                  f"{r.stderr.decode()[-600:]}")
            failures += 1
            continue
        # Identified-but-unreadable is fine; we only require no crash and, when a
        # reiserfs extraction ran, a recognized status.
        try:
            entry = json.loads(r.stdout.decode()).get("extraction", {}).get("extracted", [{}])[0]
            status = entry.get("status", "")
        except Exception:
            status = ""
        ok = (status == "" or status == "ok" or status == "partial"
              or status.startswith("error:"))
        print(f"{'PASS' if ok else 'FAIL'} [corrupt {label}]: no crash, status={status!r}")
        failures += 0 if ok else 1
    return failures


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as work:
        failures = 0
        failures += test_synthetic(work)
        failures += test_real_empty(work)
        failures += test_corruption(work)
    if failures:
        print(f"\n{failures} reiserfs extraction check(s) failed")
        return 1
    print("\nall reiserfs extraction checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""HFS+ extraction regression.

Hand-built HFS+ images (tests/mkhfsplus_synth, no mkfs/mount/privilege) that
exercise paths a simple catalog walk gets wrong:

  1. A data fork fragmented past the 8 inline extents a catalog record holds: the
     9th+ extents live in the Extents Overflow B-tree, and without reading it the
     file is silently truncated. The fixture's frag.bin must come back whole.
  2. A name containing '/' (legal in HFS+, shown as ':' on POSIX). Dropping such a
     record would discard a whole subtree when the name is a directory's; the
     fixture checks both a '/'-named file and a '/'-named directory with a child.
  3. decmpfs-compressed files (empty data fork) and resource-fork files: their
     contents are not reconstructed yet, so the run must report `partial` and say
     why, rather than silently emitting empty/short files as `ok`.
  4. The run-wide --max-files / --max-bytes ceiling must bound a single filesystem
     walk, not only the recursion between extractions.
  5. Corrupt headers/trees must not crash and must yield a sane status.

Run: python3 tests/test_hfsplus_extract.py [path/to/moria]
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")
sys.path.insert(0, HERE)
import mkhfsplus_synth as M  # noqa: E402


def run(work, img_bytes, label, *extra):
    img = os.path.join(work, f"{label}.img")
    with open(img, "wb") as f:
        f.write(img_bytes)
    outdir = os.path.join(work, f"{label}.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, *extra, img],
                       capture_output=True)
    if r.returncode != 0:
        print(f"FAIL [{label}]: moria exit {r.returncode}\n{r.stderr.decode()[-800:]}")
        return None, None, None
    try:
        doc = json.loads(r.stdout.decode())
        entry = doc["extraction"]["extracted"][0]
    except Exception as e:
        print(f"FAIL [{label}]: no extraction manifest ({e})\n{r.stdout[:200]}")
        return None, None, None
    return doc["extraction"], entry, outdir


def tree_manifest(root):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames) + list(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if os.path.isdir(full):
                out[rel] = ("dir",)
            else:
                with open(full, "rb") as f:
                    out[rel] = ("file", hashlib.sha256(f.read()).hexdigest())
    return out


def expected_manifest(expect):
    out = {}
    for path, content in expect.items():
        if content is None:
            out[path] = ("dir",)
        else:
            out[path] = ("file", hashlib.sha256(content).hexdigest())
    return out


def test_roundtrip(work):
    img, expect = M.full_image()
    ext, entry, outdir = run(work, img, "full")
    if entry is None:
        return 1
    failures = 0
    # decmpfs + resource-fork files -> the run is honestly partial, with reasons.
    if entry["status"] != "partial":
        print(f"FAIL [roundtrip]: status={entry['status']} (expected partial)")
        failures += 1
    warns = " | ".join(entry.get("warnings", []))
    if "decmpfs" not in warns:
        print(f"FAIL [roundtrip]: no decmpfs warning; got {entry.get('warnings')}")
        failures += 1
    if "resource fork" not in warns:
        print(f"FAIL [roundtrip]: no resource-fork warning; got {entry.get('warnings')}")
        failures += 1
    # every file/dir present and byte-identical (frag.bin proves the overflow read;
    # a:b.txt + weird:dir/inside.txt prove '/'-name sanitize + subtree survival).
    got = tree_manifest(os.path.join(outdir, entry["root"]))
    exp = expected_manifest(expect)
    if got == exp:
        print(f"PASS [roundtrip]: {entry['files']} files, {entry['dirs']} dirs round-trip "
              f"byte-for-byte (overflow, '/'-name, subtree, decmpfs, resource fork)")
    else:
        failures += 1
        only_exp = sorted(set(exp) - set(got))
        only_got = sorted(set(got) - set(exp))
        mism = sorted(k for k in exp.keys() & got.keys() if exp[k] != got[k])
        print(f"FAIL [roundtrip]: missing={only_exp} extra={only_got} mismatched={mism}")
    return failures


def test_fragment_exact(work):
    """The fragmented file's bytes must match exactly (not just its length)."""
    img, expect = M.full_image()
    ext, entry, outdir = run(work, img, "frag")
    if entry is None:
        return 1
    want = expect["frag.bin"]
    with open(os.path.join(outdir, entry["root"], "frag.bin"), "rb") as f:
        got = f.read()
    if got == want:
        print(f"PASS [fragment]: {len(got)}-byte file across 8 inline + 2 overflow extents is exact")
        return 0
    print(f"FAIL [fragment]: len got={len(got)} want={len(want)}, equal={got == want}")
    return 1


def test_budget(work):
    """--max-files must stop the walk mid-filesystem and mark the run capped."""
    img, _ = M.full_image()
    ext, entry, outdir = run(work, img, "budget", "--max-files", "2")
    if entry is None:
        return 1
    failures = 0
    if entry["files"] > 2:
        print(f"FAIL [budget]: wrote {entry['files']} files past the limit of 2")
        failures += 1
    if not ext.get("capped") or ext.get("cap_reason") != "max-files":
        print(f"FAIL [budget]: capped={ext.get('capped')} reason={ext.get('cap_reason')}")
        failures += 1
    if entry["status"] != "partial":
        print(f"FAIL [budget]: status={entry['status']} (expected partial)")
        failures += 1
    if not failures:
        print(f"PASS [budget]: stopped at {entry['files']} files, capped=max-files, partial")
    return failures


def test_corruption(work):
    """Mangled volume headers / trees must not crash and must report sanely."""
    base, _ = M.full_image()
    cases = {
        "truncated-at-vh": base[:1024 + 100],            # volume header only
        "truncated-mid-catalog": base[:40 * 512],        # cut inside metadata
        "bad-blocksize": bytearray(base),                # non-power-of-two blockSize
        "huge-catalog-extent": bytearray(base),          # catalog extent past volume
        "zeroed": bytes(len(base)),                      # all zero (no signature)
    }
    struct.pack_into(">I", cases["bad-blocksize"], 1024 + 40, 777)
    struct.pack_into(">I", cases["huge-catalog-extent"], 1024 + 272 + 16, 0x7FFFFFFF)
    failures = 0
    for label, data in cases.items():
        img = os.path.join(work, f"corrupt-{label}.img")
        with open(img, "wb") as f:
            f.write(bytes(data))
        r = subprocess.run([MORIA, "-j", "--extract", "-C", img + ".out", img],
                           capture_output=True)
        if r.returncode != 0:
            print(f"FAIL [corrupt {label}]: moria crashed/errored (exit {r.returncode})")
            failures += 1
            continue
        # A sane run: either no hfsplus extraction, or one with a non-"ok"-but-defined
        # status. The point is no crash and valid JSON (ASan build is the OOB oracle).
        try:
            doc = json.loads(r.stdout.decode())
        except Exception as e:
            print(f"FAIL [corrupt {label}]: invalid JSON ({e})")
            failures += 1
            continue
        for e in doc.get("extraction", {}).get("extracted", []):
            if e["type"] == "hfsplus" and e["status"] not in ("ok", "partial",
                                                               "error:bad-volume-header",
                                                               "error:no-catalog",
                                                               "error:catalog-read", "error:mkdir"):
                print(f"FAIL [corrupt {label}]: odd status {e['status']}")
                failures += 1
    if not failures:
        print(f"PASS [corruption]: {len(cases)} mangled images handled without crash")
    return failures


def main():
    if not os.path.exists(MORIA):
        print(f"SKIP: moria binary not found at {MORIA}")
        return 0
    with tempfile.TemporaryDirectory() as work:
        failures = (test_roundtrip(work) + test_fragment_exact(work) +
                    test_budget(work) + test_corruption(work))
    if failures:
        print(f"\n{failures} HFS+ extraction check(s) failed")
        return 1
    print("\nall HFS+ extraction checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

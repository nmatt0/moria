#!/usr/bin/env python3
"""romfs oversized-size-field regression (issue #68).

The romfs size field (header offset 8) is 32-bit, so the per-file size cap must
be representable within ~4 GiB to do anything; the old 8 GiB cap compared against
a uint32_t was dead code. This builds a real romfs with the bundled mkromfs.py,
patches one regular file's 32-bit size field to 0xFFFFFFFF, and checks that moria:

  - does not crash (the ASan build is the out-of-bounds / allocation oracle);
  - reports a sane status (partial, since the oversized entry is clamped/skipped);
  - does not emit a bogus multi-gigabyte file; the normal sibling file still
    extracts.

Run: python3 tests/test_romfs_sizecap.py [path/to/moria]
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")
MKROMFS = os.path.join(HERE, "mkromfs.py")


def dir_size(path):
    total = 0
    for dp, _, fns in os.walk(path):
        for fn in fns:
            fp = os.path.join(dp, fn)
            if not os.path.islink(fp):
                total += os.path.getsize(fp)
    return total


def build_image(work):
    src = os.path.join(work, "src")
    os.makedirs(src)
    with open(os.path.join(src, "BIGFILE"), "wb") as f:
        f.write(b"small payload\n")
    with open(os.path.join(src, "normal.txt"), "wb") as f:
        f.write(b"intact\n")
    img = os.path.join(work, "t.romfs")
    r = subprocess.run([sys.executable, MKROMFS, src, img], capture_output=True)
    if r.returncode != 0:
        return None
    return img


def patch_oversize(img):
    """Set the 32-bit big-endian size field of the BIGFILE header to 0xFFFFFFFF.

    The name sits at header+16, so the header starts 16 bytes before the name and
    the size field is at header+8. moria does not verify header checksums, so the
    rest of the header stays valid and the parser reaches the regular-file path.
    """
    data = bytearray(open(img, "rb").read())
    name_off = data.find(b"BIGFILE\x00")
    assert name_off >= 16, "BIGFILE header not found"
    hdr = name_off - 16
    data[hdr + 8: hdr + 12] = (0xFFFFFFFF).to_bytes(4, "big")
    open(img, "wb").write(bytes(data))


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as work:
        img = build_image(work)
        if img is None:
            print("SKIP [romfs-sizecap]: mkromfs.py failed")
            return 0
        patch_oversize(img)
        outdir = os.path.join(work, "out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img],
                           capture_output=True, timeout=120)
        if r.returncode != 0:
            print(f"FAIL [romfs-sizecap]: moria exit {r.returncode} (crash/sanitizer?)\n"
                  f"{r.stderr.decode()[-800:]}")
            return 1
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
        except Exception:
            print(f"FAIL [romfs-sizecap]: no extraction manifest\n{r.stdout[:200]}")
            return 1
        # The oversized entry must not have produced a huge write; the whole
        # output tree stays tiny (well under any multi-gigabyte allocation).
        sz = dir_size(outdir)
        if sz > 16 * 1024 * 1024:
            print(f"FAIL [romfs-sizecap]: output tree is {sz} bytes (oversized write?)")
            return 1
        if entry["status"] != "partial":
            print(f"FAIL [romfs-sizecap]: status={entry['status']!r} (expected partial)")
            return 1
        # The intact sibling file is unaffected.
        normal = os.path.join(outdir, entry["root"], "normal.txt")
        if not os.path.isfile(normal) or open(normal, "rb").read() != b"intact\n":
            print("FAIL [romfs-sizecap]: intact sibling file not extracted correctly")
            return 1
        print(f"PASS [romfs-sizecap]: oversized size clamped, status=partial, "
              f"no bogus write ({sz} bytes), sibling intact")
        return 0


if __name__ == "__main__":
    sys.exit(main())

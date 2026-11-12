#!/usr/bin/env python3
"""JFFS2 extraction regression (PR #77 — directory inode recovery).

JFFS2 is log-structured: a live inode normally has at least one inode node
carrying its mode/size, and directories are rebuilt by walking dirents from the
root inode (1). In a partial or garbage-collected capture an intermediate
directory's inode node can be missing while its dirents (in the parent) and its
children's nodes survive. The old walk dropped that directory AND its whole
subtree. PR #77 recovers it: when a dirent names an inode with no inode node but
with dirents of its own, that inode is a directory whose node was not captured,
so moria creates it and recurses.

Layers (all always-on; the nodes are hand-built, no mkfs.jffs2 needed):

  1. full          — every node present; byte-exact round-trip, status ok.
  2. drop-dir-inode — subdir's inode node removed, its dirents + children kept;
                      the subtree must be recovered byte-exact, status ok.
                      (Fails on pre-#77 moria: the subtree is lost.)
  3. drop-file-inode — a regular file's inode node removed (no children): the
                      file is genuinely unrecoverable, so it stays absent AND the
                      result must be reported partial, not ok. (Guards the
                      truncation-signal fix layered onto PR #77: without it the
                      silently-dropped file is reported as a complete extraction.)
  4. big-endian     — layer 2 again on a BE image, exercising endian detection.
  5. corruption     — mangled node bytes must never crash (ASan is the oracle).
  6. real round-trip — mkfs.jffs2 image, byte-exact; self-skips if absent.

Run: python3 tests/test_jffs2.py [path/to/moria]
"""
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")

JFFS2_MAGIC = 0x1985
NODETYPE_DIRENT = 0xE001
NODETYPE_INODE = 0xE002
COMPR_NONE = 0
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000
ROOT_INO = 1

# JFFS2 header CRC: table CRC, init 0, no final inversion (matches crc32_jffs2 /
# gen_samples._jffs2_crc).
_CRC_T = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC_T.append(_c & 0xFFFFFFFF)


def _crc(data):
    crc = 0
    for x in data:
        crc = _CRC_T[(crc ^ x) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def _align4(x):
    return (x + 3) & ~3


class Img:
    """Accumulates 4-byte-aligned JFFS2 nodes into one little/big-endian image."""

    def __init__(self, endian="<"):
        self.e = endian
        self.buf = bytearray()

    def _emit(self, node):
        # hdr_crc over the first 8 bytes (common header, crc field zeroed).
        struct.pack_into(self.e + "I", node, 8, _crc(bytes(node[:8])))
        self.buf += node
        while len(self.buf) % 4:
            self.buf.append(0xFF)  # erased-flash pad between nodes

    def inode(self, ino, version, mode, data=b""):
        isize = len(data)
        totlen = 68 + isize
        n = bytearray(totlen)
        struct.pack_into(self.e + "H", n, 0, JFFS2_MAGIC)
        struct.pack_into(self.e + "H", n, 2, NODETYPE_INODE)
        struct.pack_into(self.e + "I", n, 4, totlen)
        struct.pack_into(self.e + "I", n, 12, ino)
        struct.pack_into(self.e + "I", n, 16, version)
        struct.pack_into(self.e + "I", n, 20, mode)
        struct.pack_into(self.e + "I", n, 28, isize)      # isize
        struct.pack_into(self.e + "I", n, 44, 0)          # data offset in file
        struct.pack_into(self.e + "I", n, 48, isize)      # csize
        struct.pack_into(self.e + "I", n, 52, isize)      # dsize
        n[56] = COMPR_NONE
        n[68:68 + isize] = data
        self._emit(n)

    def dirent(self, pino, version, ino, name):
        nm = name.encode()
        totlen = 40 + len(nm)
        n = bytearray(totlen)
        struct.pack_into(self.e + "H", n, 0, JFFS2_MAGIC)
        struct.pack_into(self.e + "H", n, 2, NODETYPE_DIRENT)
        struct.pack_into(self.e + "I", n, 4, totlen)
        struct.pack_into(self.e + "I", n, 12, pino)
        struct.pack_into(self.e + "I", n, 16, version)
        struct.pack_into(self.e + "I", n, 20, ino)
        n[28] = len(nm)
        n[40:40 + len(nm)] = nm
        self._emit(n)


# Shared layout:  /top.txt  /subdir/a.txt  /subdir/nested/b.txt
A_TXT = b"file a contents\n"
B_TXT = b"deeply nested file b\n"
TOP_TXT = b"top level file\n"

FULL_TREE = {
    "top.txt": ("file", hashlib.sha256(TOP_TXT).hexdigest()),
    "subdir": ("dir",),
    "subdir/a.txt": ("file", hashlib.sha256(A_TXT).hexdigest()),
    "subdir/nested": ("dir",),
    "subdir/nested/b.txt": ("file", hashlib.sha256(B_TXT).hexdigest()),
}


def build(endian="<", drop_inos=()):
    """Build the image; omit the INODE node for each ino in drop_inos (dirents
    and every other node are kept)."""
    im = Img(endian)
    # Inode (metadata/data) nodes.
    inodes = [
        (ROOT_INO, S_IFDIR, b""),   # ino 1: root
        (2, S_IFDIR, b""),          # ino 2: subdir
        (3, S_IFREG, A_TXT),        # ino 3: subdir/a.txt
        (4, S_IFDIR, b""),          # ino 4: subdir/nested
        (5, S_IFREG, B_TXT),        # ino 5: subdir/nested/b.txt
        (6, S_IFREG, TOP_TXT),      # ino 6: top.txt
    ]
    for ino, mode, data in inodes:
        if ino in drop_inos:
            continue
        im.inode(ino, 1, mode, data)
    # Dirents, keyed by parent inode.
    im.dirent(ROOT_INO, 1, 2, "subdir")
    im.dirent(ROOT_INO, 1, 6, "top.txt")
    im.dirent(2, 1, 3, "a.txt")
    im.dirent(2, 1, 4, "nested")
    im.dirent(4, 1, 5, "b.txt")
    return bytes(im.buf)


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
    img = os.path.join(work, f"{label}.img")
    with open(img, "wb") as f:
        f.write(img_bytes)
    outdir = os.path.join(work, f"{label}.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img],
                       capture_output=True, timeout=60)
    if r.returncode != 0:
        print(f"FAIL [{label}]: moria exit {r.returncode}\n{r.stderr.decode()[-800:]}")
        return None, None
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception as e:
        print(f"FAIL [{label}]: no extraction manifest ({e})\n{r.stdout[:200]}")
        return None, None
    return entry, outdir


def _check_tree(label, entry, outdir, expected, want_status):
    if entry["status"] != want_status:
        print(f"FAIL [{label}]: status={entry['status']!r}, want {want_status!r}")
        return 1
    got = tree_manifest(os.path.join(outdir, entry["root"]))
    if got != expected:
        only_exp = sorted(set(expected) - set(got))
        only_got = sorted(set(got) - set(expected))
        mism = sorted(k for k in expected.keys() & got.keys() if expected[k] != got[k])
        print(f"FAIL [{label}]: missing={only_exp} extra={only_got} mismatched={mism}")
        return 1
    print(f"PASS [{label}]: {entry['files']} files, {entry['dirs']} dirs, status {entry['status']}")
    return 0


def test_full(work):
    entry, outdir = extract(work, build(), "full")
    if entry is None:
        return 1
    return _check_tree("full", entry, outdir, FULL_TREE, "ok")


def test_drop_dir_inode(work, endian="<", label="drop-dir-inode"):
    # subdir (ino 2) has no inode node; its dirents + children survive. The whole
    # subtree must be recovered byte-exact. Pre-#77 moria drops it entirely.
    entry, outdir = extract(work, build(endian, drop_inos={2}), label)
    if entry is None:
        return 1
    return _check_tree(label, entry, outdir, FULL_TREE, "ok")


def test_drop_file_inode(work):
    # top.txt (ino 6) has no inode node and no children: genuinely unrecoverable.
    # It must be absent, and the extraction must be reported partial (a dropped
    # object is not a complete extraction).
    expected = {k: v for k, v in FULL_TREE.items() if k != "top.txt"}
    entry, outdir = extract(work, build(drop_inos={6}), "drop-file-inode")
    if entry is None:
        return 1
    return _check_tree("drop-file-inode", entry, outdir, expected, "partial")


def test_corruption(work):
    base = bytearray(build())
    cases = {
        "truncated-mid": bytes(base[:len(base) // 2]),
        "garbage-tail": bytes(base) + bytes((i * 37) & 0xFF for i in range(4096)),
        "flipped-totlens": bytearray(base),
        "zeroed-mid": bytearray(base),
    }
    f = cases["flipped-totlens"]
    for i in range(0, len(f) - 8, 64):
        if struct.unpack_from("<H", f, i)[0] == JFFS2_MAGIC:
            struct.pack_into("<I", f, i + 4, 0xFFFFFFF0)  # absurd totlen
    z = cases["zeroed-mid"]
    z[len(z) // 3:2 * len(z) // 3] = b"\x00" * (2 * len(z) // 3 - len(z) // 3)
    failures = 0
    for label, data in cases.items():
        img = os.path.join(work, f"corrupt_{label}.img")
        with open(img, "wb") as fh:
            fh.write(bytes(data))
        outdir = os.path.join(work, f"corrupt_{label}.out")
        try:
            r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img],
                               capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            print(f"FAIL [corrupt {label}]: timeout (hang)")
            failures += 1
            continue
        if r.returncode != 0:
            print(f"FAIL [corrupt {label}]: exit {r.returncode} (crash/sanitizer?)\n"
                  f"{r.stderr.decode()[-600:]}")
            failures += 1
            continue
        print(f"PASS [corrupt {label}]: no crash")
    return failures


def test_real(work):
    """mkfs.jffs2 builds a genuine image; moria must round-trip it byte-exact."""
    if not shutil.which("mkfs.jffs2"):
        print("SKIP [real]: mkfs.jffs2 (mtd-utils) not installed")
        return 0
    src = os.path.join(work, "realsrc")
    os.makedirs(os.path.join(src, "subdir", "nested"))
    with open(os.path.join(src, "top.txt"), "wb") as f:
        f.write(TOP_TXT)
    with open(os.path.join(src, "subdir", "a.txt"), "wb") as f:
        f.write(A_TXT)
    with open(os.path.join(src, "subdir", "nested", "b.txt"), "wb") as f:
        f.write(B_TXT)
    os.symlink("a.txt", os.path.join(src, "subdir", "link"))
    img = os.path.join(work, "real.jffs2")
    r = subprocess.run(["mkfs.jffs2", "-r", src, "-o", img, "-e", "0x10000", "-l"],
                       capture_output=True)
    if r.returncode != 0:
        print(f"SKIP [real]: mkfs.jffs2 failed\n{r.stderr.decode()[-300:]}")
        return 0
    entry, outdir = extract(work, open(img, "rb").read(), "real")
    if entry is None:
        return 1
    expected = dict(FULL_TREE)
    expected["subdir/link"] = ("link", "a.txt")
    return _check_tree("real", entry, outdir, expected, "ok")


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as work:
        failures = 0
        failures += test_full(work)
        failures += test_drop_dir_inode(work)
        failures += test_drop_dir_inode(work, ">", "drop-dir-inode-be")
        failures += test_drop_file_inode(work)
        failures += test_corruption(work)
        failures += test_real(work)
    if failures:
        print(f"\n{failures} jffs2 extraction check(s) failed")
        return 1
    print("\nall jffs2 extraction checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""SquashFS extraction regression: build a known tree, squash it with each
compressor, extract with moria, and assert the tree round-trips byte-for-byte.

Deterministic and self-contained, but needs `mksquashfs` (squashfs-tools) to
build fixtures. Skips (exit 0) if mksquashfs is absent so it never blocks a
build on a host without it. Run: python3 tests/test_extract.py
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")
COMPRESSORS = ["gzip", "xz", "lz4", "zstd"]


def have(tool):
    return shutil.which(tool) is not None


def build_tree(root):
    """A tree that exercises fragments, multi-block files, sparse-ish data,
    subdirs, symlinks, and non-default modes."""
    os.makedirs(os.path.join(root, "etc"))
    os.makedirs(os.path.join(root, "usr", "bin"))
    os.makedirs(os.path.join(root, "empty"))
    # small file -> stored as a fragment
    with open(os.path.join(root, "etc", "hostname"), "wb") as f:
        f.write(b"moria-test\n")
    # highly compressible medium file (multiple metadata/data blocks)
    with open(os.path.join(root, "etc", "zeros.dat"), "wb") as f:
        f.write(b"\x00" * (300 * 1024))
    # incompressible large file -> exercises the uncompressed-block flag path
    with open(os.path.join(root, "usr", "bin", "rand.bin"), "wb") as f:
        f.write(os.urandom(400 * 1024))
    # exec-mode file (readability must survive extraction)
    p = os.path.join(root, "usr", "bin", "run.sh")
    with open(p, "wb") as f:
        f.write(b"#!/bin/sh\necho hi\n")
    os.chmod(p, 0o755)
    # symlinks (relative + absolute-looking target, stored verbatim)
    os.symlink("hostname", os.path.join(root, "etc", "hn.lnk"))
    os.symlink("../etc/hostname", os.path.join(root, "usr", "bin", "hn2.lnk"))


def tree_manifest(root):
    """(relpath -> descriptor) for every entry, for comparison."""
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


def test_cpio(work, src, expected):
    """Pack the tree as a newc cpio, extract with moria, compare. Needs `cpio`.
    Returns failure count (0 = pass or skipped)."""
    if not have("cpio"):
        print("SKIP [cpio]: cpio tool not installed")
        return 0
    img = os.path.join(work, "test.cpio")
    with open(img, "wb") as out:
        find = subprocess.Popen(["find", "."], cwd=src, stdout=subprocess.PIPE)
        r = subprocess.run(["cpio", "-o", "-H", "newc"], cwd=src, stdin=find.stdout,
                           stdout=out, stderr=subprocess.DEVNULL)
        find.stdout.close()
        find.wait()
    if r.returncode != 0:
        print("SKIP [cpio]: cpio pack failed")
        return 0

    outdir = os.path.join(work, "cpio.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [cpio]: no extraction manifest\n{r.stdout[:200]}")
        return 1
    if entry["status"] != "ok":
        print(f"FAIL [cpio]: status={entry['status']}")
        return 1
    got = tree_manifest(os.path.join(outdir, entry["root"]))
    if got == expected:
        print(f"PASS [cpio]: {entry['files']} files, {entry['dirs']} dirs, "
              f"{entry['symlinks']} symlinks")
        return 0
    only_exp = set(expected) - set(got)
    only_got = set(got) - set(expected)
    mism = {k for k in expected.keys() & got.keys() if expected[k] != got[k]}
    print(f"FAIL [cpio]: missing={sorted(only_exp)} extra={sorted(only_got)} "
          f"mismatched={sorted(mism)}")
    return 1


def test_ext(work, src, expected):
    """Build ext4 (extents) and ext2 (indirect blocks) images from the tree with
    mke2fs -d, extract with moria, compare. Needs `mke2fs`. mke2fs adds an empty
    lost+found we ignore. Returns failure count (0 = pass or skipped)."""
    if not have("mke2fs"):
        print("SKIP [ext]: mke2fs (e2fsprogs) not installed")
        return 0
    failures = 0
    variants = [("ext4", ["-t", "ext4"]), ("ext2", ["-t", "ext2", "-O", "^extent"])]
    for label, opts in variants:
        img = os.path.join(work, f"{label}.img")
        r = subprocess.run(["mke2fs", "-q", "-F", *opts, "-b", "4096", "-d", src, img, "16M"],
                           capture_output=True)
        if r.returncode != 0:
            print(f"SKIP [{label}]: mke2fs failed")
            continue
        outdir = os.path.join(work, f"{label}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
        except Exception:
            print(f"FAIL [{label}]: no extraction manifest\n{r.stdout[:200]}")
            failures += 1
            continue
        if entry["status"] != "ok":
            print(f"FAIL [{label}]: status={entry['status']}")
            failures += 1
            continue
        got = tree_manifest(os.path.join(outdir, entry["root"]))
        got = {k: v for k, v in got.items() if not k.startswith("lost+found")}
        if got == expected:
            print(f"PASS [{label}]: {entry['files']} files, {entry['dirs']} dirs, "
                  f"{entry['symlinks']} symlinks")
        else:
            failures += 1
            only_exp = set(expected) - set(got)
            only_got = set(got) - set(expected)
            mism = {k for k in expected.keys() & got.keys() if expected[k] != got[k]}
            print(f"FAIL [{label}]: missing={sorted(only_exp)} extra={sorted(only_got)} "
                  f"mismatched={sorted(mism)}")
    return failures


def test_jffs2(work, src, expected):
    """Build jffs2 images (none/zlib/lzo) from the tree with mkfs.jffs2, extract
    with moria, compare. Needs `mkfs.jffs2`. The lzo variant exercises moria's
    internal LZO1X decompressor end-to-end. Returns failure count."""
    if not have("mkfs.jffs2"):
        print("SKIP [jffs2]: mkfs.jffs2 (mtd-utils) not installed")
        return 0
    failures = 0
    for comp in ("none", "zlib", "lzo"):
        img = os.path.join(work, f"j_{comp}.jffs2")
        r = subprocess.run(["mkfs.jffs2", "-r", src, "-o", img, "-e", "128", "-n",
                            "-q", "-X", comp], capture_output=True)
        if r.returncode != 0:
            print(f"SKIP [jffs2-{comp}]: mkfs.jffs2 failed")
            continue
        outdir = os.path.join(work, f"j_{comp}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
        except Exception:
            print(f"FAIL [jffs2-{comp}]: no extraction manifest\n{r.stdout[:200]}")
            failures += 1
            continue
        got = tree_manifest(os.path.join(outdir, entry["root"]))
        if got == expected:
            print(f"PASS [jffs2-{comp}]: {entry['files']} files, {entry['dirs']} dirs, "
                  f"{entry['symlinks']} symlinks")
        else:
            failures += 1
            only_exp = set(expected) - set(got)
            only_got = set(got) - set(expected)
            mism = {k for k in expected.keys() & got.keys() if expected[k] != got[k]}
            print(f"FAIL [jffs2-{comp}]: missing={sorted(only_exp)} extra={sorted(only_got)} "
                  f"mismatched={sorted(mism)}")
    return failures


def test_ubifs(work, src, expected):
    """Build UBIFS images (none/lzo/zlib/zstd) with mkfs.ubifs, extract with
    moria, compare. Needs `mkfs.ubifs`. lzo exercises the internal LZO1X and zlib
    the raw-deflate path. Returns failure count."""
    if not have("mkfs.ubifs"):
        print("SKIP [ubifs]: mkfs.ubifs (mtd-utils) not installed")
        return 0
    failures = 0
    for comp in ("none", "lzo", "zlib", "zstd"):
        img = os.path.join(work, f"u_{comp}.ubifs")
        r = subprocess.run(["mkfs.ubifs", "-r", src, "-m", "2048", "-e", "126976",
                            "-c", "512", "-x", comp, "-o", img], capture_output=True)
        if r.returncode != 0:
            print(f"SKIP [ubifs-{comp}]: mkfs.ubifs failed")
            continue
        outdir = os.path.join(work, f"u_{comp}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
        except Exception:
            print(f"FAIL [ubifs-{comp}]: no extraction manifest\n{r.stdout[:200]}")
            failures += 1
            continue
        got = tree_manifest(os.path.join(outdir, entry["root"]))
        if got == expected:
            print(f"PASS [ubifs-{comp}]: {entry['files']} files, {entry['dirs']} dirs, "
                  f"{entry['symlinks']} symlinks")
        else:
            failures += 1
            only_exp = set(expected) - set(got)
            only_got = set(got) - set(expected)
            mism = {k for k in expected.keys() & got.keys() if expected[k] != got[k]}
            print(f"FAIL [ubifs-{comp}]: missing={sorted(only_exp)} extra={sorted(only_got)} "
                  f"mismatched={sorted(mism)}")
    return failures


def test_tar(work, src, expected):
    """Pack the tree with GNU tar (gnu/pax/ustar), extract with moria, compare.
    Needs `tar`. Exercises long names, prefix, and pax path records. Returns
    failure count."""
    if not have("tar"):
        print("SKIP [tar]: tar not installed")
        return 0
    failures = 0
    for fmt in ("gnu", "pax", "ustar"):
        img = os.path.join(work, f"t_{fmt}.tar")
        r = subprocess.run(["tar", f"--format={fmt}", "-cf", img, "."], cwd=src,
                           capture_output=True)
        if r.returncode != 0:
            print(f"SKIP [tar-{fmt}]: tar create failed")
            continue
        outdir = os.path.join(work, f"t_{fmt}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
        except Exception:
            print(f"FAIL [tar-{fmt}]: no extraction manifest")
            failures += 1
            continue
        got = tree_manifest(os.path.join(outdir, entry["root"]))
        got = {k: v for k, v in got.items() if k != "."}
        if got == expected:
            print(f"PASS [tar-{fmt}]: {entry['files']} files, {entry['dirs']} dirs, "
                  f"{entry['symlinks']} symlinks")
        else:
            failures += 1
            print(f"FAIL [tar-{fmt}]: missing={sorted(set(expected)-set(got))[:4]} "
                  f"extra={sorted(set(got)-set(expected))[:4]} "
                  f"mismatched={sorted(k for k in expected.keys()&got.keys() if expected[k]!=got[k])[:4]}")
    return failures


def test_romfs(work, src, expected):
    """Build a romfs image with the bundled mkromfs.py, extract with moria,
    compare. Self-contained (no external builder). Returns failure count."""
    img = os.path.join(work, "test.romfs")
    r = subprocess.run([sys.executable, os.path.join(HERE, "mkromfs.py"), src, img],
                       capture_output=True)
    if r.returncode != 0:
        print(f"SKIP [romfs]: mkromfs.py failed\n{r.stderr[:200]}")
        return 0
    outdir = os.path.join(work, "romfs.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [romfs]: no extraction manifest")
        return 1
    got = tree_manifest(os.path.join(outdir, entry["root"]))
    if got == expected:
        print(f"PASS [romfs]: {entry['files']} files, {entry['dirs']} dirs, "
              f"{entry['symlinks']} symlinks")
        return 0
    print(f"FAIL [romfs]: missing={sorted(set(expected)-set(got))[:4]} "
          f"extra={sorted(set(got)-set(expected))[:4]} "
          f"mismatched={sorted(k for k in expected.keys()&got.keys() if expected[k]!=got[k])[:4]}")
    return 1


def test_yaffs2(work, src, expected):
    """Build a YAFFS2 image with mkyaffs2 (2K page / 64B OOB), extract with moria,
    compare. Needs `mkyaffs2` (yaffs2utils). Returns failure count."""
    if not have("mkyaffs2"):
        print("SKIP [yaffs2]: mkyaffs2 (yaffs2utils) not installed")
        return 0
    img = os.path.join(work, "test.yaffs2")
    r = subprocess.run(["mkyaffs2", "-p", "2048", "-s", "64", src, img], capture_output=True)
    if r.returncode != 0:
        print("SKIP [yaffs2]: mkyaffs2 failed")
        return 0
    outdir = os.path.join(work, "yaffs2.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [yaffs2]: no extraction manifest\n{r.stdout[:200]}")
        return 1
    got = tree_manifest(os.path.join(outdir, entry["root"]))
    if got == expected:
        print(f"PASS [yaffs2]: {entry['files']} files, {entry['dirs']} dirs, "
              f"{entry['symlinks']} symlinks")
        return 0
    print(f"FAIL [yaffs2]: missing={sorted(set(expected)-set(got))[:4]} "
          f"extra={sorted(set(got)-set(expected))[:4]} "
          f"mismatched={sorted(k for k in expected.keys()&got.keys() if expected[k]!=got[k])[:4]}")
    return 1


def test_yaffs2_embedded(work, src):
    """A real YAFFS2 image placed at a nonzero offset inside a larger blob must be
    identified as yaffs2 at that offset. Regression for the flat scan only finding
    yaffs2 at offset 0 (0xFFFF anchor was gated to stream start). Needs `mkyaffs2`.
    Returns failure count."""
    if not have("mkyaffs2"):
        print("SKIP [yaffs2-embedded]: mkyaffs2 (yaffs2utils) not installed")
        return 0
    img = os.path.join(work, "embed.yaffs2")
    r = subprocess.run(["mkyaffs2", "-p", "2048", "-s", "64", src, img], capture_output=True)
    if r.returncode != 0:
        print("SKIP [yaffs2-embedded]: mkyaffs2 failed")
        return 0
    with open(img, "rb") as f:
        fs = f.read()
    off = 3 * 1024 * 1024  # a nonzero, block-aligned offset
    blob = os.path.join(work, "embedded_fw.bin")
    with open(blob, "wb") as f:
        f.write(os.urandom(off) + fs + os.urandom(64 * 1024))
    r = subprocess.run([MORIA, "-j", blob], capture_output=True)
    try:
        findings = json.loads(r.stdout.decode())["findings"]
    except Exception:
        print(f"FAIL [yaffs2-embedded]: no JSON\n{r.stdout[:200]}")
        return 1
    hit = [f for f in findings if f["type"] == "yaffs2" and f["offset"] == off]
    if not hit:
        got = sorted({(f["type"], hex(f["offset"])) for f in findings})
        print(f"FAIL [yaffs2-embedded]: no yaffs2 at 0x{off:x}; findings={got[:6]}")
        return 1
    # Sizing: a confirmed OOB geometry must size the finding to ~the whole image
    # (the walk trims trailing erased padding, so allow a small shortfall), not a
    # single 2 KiB chunk.
    size = hit[0].get("size", 0)
    if not (len(fs) * 0.5 <= size <= len(fs)):
        print(f"FAIL [yaffs2-embedded]: bad size 0x{size:x} for a 0x{len(fs):x} image")
        return 1
    # Interior masking: nothing inside [off, off+size) may surface as its own
    # finding (files in the image must not leak as top-level hits).
    leaked = [f for f in findings if f is not hit[0] and off < f["offset"] < off + size]
    if leaked:
        got = sorted({(f["type"], hex(f["offset"])) for f in leaked})
        print(f"FAIL [yaffs2-embedded]: {len(leaked)} interior findings leaked: {got[:6]}")
        return 1
    print(f"PASS [yaffs2-embedded]: yaffs2 @0x{off:x} sized 0x{size:x}, interior masked")
    return 0


def test_yaffs2_dataonly(work, src):
    """A YAFFS2 image whose OOB/spare has been stripped (a `dd`/mtdblock dump) is
    not sizable or extractable, but its object headers survive. moria must still
    identify it as ONE yaffs2 region (not a swarm of per-header fragments) and
    attach the `yaffs2-no-oob` diagnostic pointing at re-dumping with spare.
    Needs `mkyaffs2`. Returns failure count."""
    if not have("mkyaffs2"):
        print("SKIP [yaffs2-dataonly]: mkyaffs2 (yaffs2utils) not installed")
        return 0
    img = os.path.join(work, "oob.yaffs2")
    page, spare = 2048, 64
    r = subprocess.run(["mkyaffs2", "-p", str(page), "-s", str(spare), src, img],
                       capture_output=True)
    if r.returncode != 0:
        print("SKIP [yaffs2-dataonly]: mkyaffs2 failed")
        return 0
    with open(img, "rb") as f:
        oob = f.read()
    # Strip the spare after every page -> a data-only dump (no per-chunk tags).
    stride = page + spare
    data = b"".join(oob[i:i + page] for i in range(0, len(oob), stride))
    off = 1024 * 1024
    blob = os.path.join(work, "dataonly_fw.bin")
    with open(blob, "wb") as f:
        f.write(b"\x00" * off + data + b"\x00" * (256 * 1024))
    r = subprocess.run([MORIA, "-j", blob], capture_output=True)
    try:
        findings = json.loads(r.stdout.decode())["findings"]
    except Exception:
        print(f"FAIL [yaffs2-dataonly]: no JSON\n{r.stdout[:200]}")
        return 1
    y = [f for f in findings if f["type"] == "yaffs2"]
    if len(y) != 1:
        print(f"FAIL [yaffs2-dataonly]: expected 1 yaffs2 region, got {len(y)}")
        return 1
    codes = [d["code"] for d in y[0].get("diagnostics", [])]
    if "yaffs2-no-oob" not in codes:
        print(f"FAIL [yaffs2-dataonly]: no yaffs2-no-oob diagnostic; got {codes}")
        return 1
    # Human rendering: the NOTES tag and the diagnostics section must appear, and
    # a warning must NOT trip the errors-only top banner.
    h = subprocess.run([MORIA, "-H", blob], capture_output=True).stdout.decode()
    if "[warn: no-oob]" not in h or "diagnostics:" not in h:
        print(f"FAIL [yaffs2-dataonly]: human output missing tag/section")
        return 1
    if "error" in h.split("diagnostics:")[0].lower():
        print(f"FAIL [yaffs2-dataonly]: a warning tripped the errors-only banner")
        return 1
    print(f"PASS [yaffs2-dataonly]: 1 region @0x{y[0]['offset']:x}, diagnostic + human rendering")
    return 0


def _extra_header_yaffs2(nfiles=16, with_root=False, erased_tail=0):
    """Build a minimal YAFFS2 image (2048p/64 OOB, tag_off 2) that uses yaffs2's
    *extra-header-info* tag encoding: a header chunk stores chunkId with bit 31
    set and the parent in the low bits, and packs the object type into the top
    nibble of objectId. Real devices (e.g. Wisenet cameras) write this; a plain
    mkyaffs2 does not, so it is synthesized here. Layout per file: one header
    chunk then one data chunk. Returns image bytes."""
    import struct
    PAGE, SPARE, TAGOFF, FLAG = 2048, 64, 2, 0x80000000
    def chunk(data, seq, objid, chunkid, bc):
        page = data.ljust(PAGE, b"\x00")
        spare = bytearray(SPARE)
        struct.pack_into("<IIII", spare, TAGOFF, seq, objid, chunkid, bc)
        return bytes(page) + bytes(spare)
    def header(objid, otype, parent, name, size):
        d = bytearray(PAGE)
        struct.pack_into("<I", d, 0, otype)          # OH_TYPE
        struct.pack_into("<I", d, 4, parent)         # OH_PARENT
        struct.pack_into("<H", d, 8, 0xFFFF)         # deprecated sum
        nm = name.encode()[:255]
        d[10:10 + len(nm)] = nm
        struct.pack_into("<I", d, 268, 0o644)        # OH_MODE
        struct.pack_into("<I", d, 292, size)         # OH_FILESIZE
        # tag: type packed into objId top nibble, chunkId = FLAG|parent
        return chunk(bytes(d), objid, (otype << 28) | objid, FLAG | parent, 0xFFFF)
    out = bytearray()
    for i in range(nfiles):
        oid = 2 + i
        body = f"contents of file {i}\n".encode()
        out += header(oid, 1, 1, f"file{i:02d}.txt", len(body))       # TYPE_FILE, parent=root(1)
        out += chunk(body, oid, oid, 1, len(body))                    # data chunk 1 (no flag)
    if with_root:
        # Root directory: object 1, parent 0. Placed mid-stream (as on a real
        # device, where the anchor lands on a file header and the parent-0 root
        # appears later in the chunk run — it must not break the run).
        out += header(1, 3, 0, "", 0)                                 # TYPE_DIR, parent 0
    out += b"\xff" * (2112 * erased_tail)                             # erased NAND tail
    return bytes(out)


def test_yaffs2_extra_header(work):
    """A YAFFS2 image using the extra-header-info tag encoding must be identified
    as an OOB (sized, no `yaffs2-no-oob` diagnostic) region AND extract its files.
    Regression for header chunks whose stored chunkId is not literally 0.
    Self-contained. Returns failure count."""
    img = _extra_header_yaffs2(16)
    off = 2112 * 512  # a chunk-grid-aligned nonzero offset
    blob = os.path.join(work, "eh_yaffs2.bin")
    with open(blob, "wb") as f:
        # Trailing junk (< one chunk) makes (filesize - off) NOT stride-aligned, so
        # extraction succeeds only if it bounds to the finding's sized region, not
        # to EOF (regression for the extractor's even-division gate on the whole file).
        f.write(b"\x00" * off + img + b"\xab" * 500)
    r = subprocess.run([MORIA, "-j", blob], capture_output=True)
    try:
        findings = json.loads(r.stdout.decode())["findings"]
    except Exception:
        print(f"FAIL [yaffs2-extra-header]: no JSON\n{r.stdout[:200]}")
        return 1
    y = [f for f in findings if f["type"] == "yaffs2" and f["offset"] == off]
    if not y:
        print(f"FAIL [yaffs2-extra-header]: not identified at 0x{off:x}")
        return 1
    if any(d["code"] == "yaffs2-no-oob" for d in y[0].get("diagnostics", [])):
        print(f"FAIL [yaffs2-extra-header]: flagged no-oob despite valid OOB tags")
        return 1
    outdir = os.path.join(work, "eh.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, blob], capture_output=True)
    try:
        ex = [e for e in json.loads(r.stdout.decode())["extraction"]["extracted"]
              if e["type"] == "yaffs2"]
    except Exception:
        print(f"FAIL [yaffs2-extra-header]: no extraction manifest\n{r.stdout[:200]}")
        return 1
    if not ex or ex[0]["files"] != 16:
        print(f"FAIL [yaffs2-extra-header]: expected 16 files, got {ex and ex[0].get('files')}")
        return 1
    print(f"PASS [yaffs2-extra-header]: identified OOB @0x{off:x}, extracted {ex[0]['files']} files")
    return 0


def test_yaffs2_sparse(work):
    """A *sparse* extra-header YAFFS2 image — a few files (plus a parent-0 root
    dir) in a large mostly-erased volume — must still identify as OOB (no
    no-oob diagnostic) and extract. Regression for the content-run floor being
    too high for sparse flash and for the parent-0 root breaking the run.
    The sized region must trim the erased tail. Self-contained."""
    nfiles, tail = 3, 2000
    img = _extra_header_yaffs2(nfiles, with_root=True, erased_tail=tail)
    content_chunks = 1 + nfiles * 2  # root header + (header+data) per file
    want_size = content_chunks * 2112
    off = 2112 * 300
    blob = os.path.join(work, "sparse_yaffs2.bin")
    with open(blob, "wb") as f:
        f.write(b"\x00" * off + img)
    r = subprocess.run([MORIA, "-j", blob], capture_output=True)
    try:
        findings = json.loads(r.stdout.decode())["findings"]
    except Exception:
        print(f"FAIL [yaffs2-sparse]: no JSON\n{r.stdout[:200]}")
        return 1
    y = [f for f in findings if f["type"] == "yaffs2" and f["offset"] == off]
    if not y:
        print(f"FAIL [yaffs2-sparse]: not identified at 0x{off:x}")
        return 1
    if any(d["code"] == "yaffs2-no-oob" for d in y[0].get("diagnostics", [])):
        print(f"FAIL [yaffs2-sparse]: sparse OOB image flagged no-oob")
        return 1
    if y[0].get("size") != want_size:
        print(f"FAIL [yaffs2-sparse]: size {y[0].get('size')} != {want_size} (erased tail not trimmed?)")
        return 1
    outdir = os.path.join(work, "sparse.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, blob], capture_output=True)
    try:
        ex = [e for e in json.loads(r.stdout.decode())["extraction"]["extracted"]
              if e["type"] == "yaffs2"]
    except Exception:
        print(f"FAIL [yaffs2-sparse]: no extraction manifest")
        return 1
    if not ex or ex[0]["files"] != nfiles:
        print(f"FAIL [yaffs2-sparse]: expected {nfiles} files, got {ex and ex[0].get('files')}")
        return 1
    print(f"PASS [yaffs2-sparse]: OOB @0x{off:x}, tail trimmed to {want_size}B, extracted {nfiles} files")
    return 0


def test_verity(work):
    """A dm-verity superblock must be identified and sized to superblock + full
    hash tree (computed from data_blocks / block sizes / digest size). Self-
    contained (no external builder). Returns failure count."""
    import struct
    page, ds = 4096, 32           # hash_block_size, sha256 digest
    data_blocks = 300000
    # hash tree: ceil-fan-out by (page/ds) per level until one root block.
    per = page // ds
    tree, blocks = 0, data_blocks
    while blocks > 1:
        blocks = (blocks + per - 1) // per
        tree += blocks
    want = (1 + tree) * page      # superblock block + tree
    sb = bytearray(page)
    sb[0:8] = b"verity\x00\x00"
    struct.pack_into("<I", sb, 8, 1)          # version
    struct.pack_into("<I", sb, 12, 1)         # hash_type
    sb[32:38] = b"sha256"
    struct.pack_into("<I", sb, 64, 4096)      # data_block_size
    struct.pack_into("<I", sb, 68, page)      # hash_block_size
    struct.pack_into("<Q", sb, 72, data_blocks)
    struct.pack_into("<H", sb, 80, 32)        # salt_size
    blob = os.path.join(work, "verity.bin")
    with open(blob, "wb") as f:
        f.write(bytes(sb) + b"\x00" * (want + page))  # room so size is not clamped
    r = subprocess.run([MORIA, "-j", blob], capture_output=True)
    try:
        findings = json.loads(r.stdout.decode())["findings"]
    except Exception:
        print(f"FAIL [verity]: no JSON\n{r.stdout[:200]}")
        return 1
    v = [f for f in findings if f["type"] == "verity"]
    if len(v) != 1 or v[0]["offset"] != 0:
        print(f"FAIL [verity]: expected one verity @0, got {[(f['type'], f['offset']) for f in v]}")
        return 1
    if v[0].get("size") != want:
        print(f"FAIL [verity]: size {v[0].get('size')} != computed {want}")
        return 1
    if v[0].get("label") != "sha256":
        print(f"FAIL [verity]: label {v[0].get('label')!r} != 'sha256'")
        return 1
    print(f"PASS [verity]: identified, sized {want} B (superblock + hash tree)")
    return 0


def test_cramfs(work, src, expected):
    """Build a cramfs image with mkfs.cramfs, extract with moria, compare. Needs
    `mkfs.cramfs` (util-linux). Exercises zlib block decompression. Returns
    failure count."""
    if not have("mkfs.cramfs"):
        print("SKIP [cramfs]: mkfs.cramfs (util-linux) not installed")
        return 0
    img = os.path.join(work, "test.cramfs")
    r = subprocess.run(["mkfs.cramfs", src, img], capture_output=True)
    if r.returncode != 0:
        print("SKIP [cramfs]: mkfs.cramfs failed")
        return 0
    outdir = os.path.join(work, "cramfs.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [cramfs]: no extraction manifest\n{r.stdout[:200]}")
        return 1
    got = tree_manifest(os.path.join(outdir, entry["root"]))
    if got == expected:
        print(f"PASS [cramfs]: {entry['files']} files, {entry['dirs']} dirs, "
              f"{entry['symlinks']} symlinks")
        return 0
    print(f"FAIL [cramfs]: missing={sorted(set(expected)-set(got))[:4]} "
          f"extra={sorted(set(got)-set(expected))[:4]} "
          f"mismatched={sorted(k for k in expected.keys()&got.keys() if expected[k]!=got[k])[:4]}")
    return 1


def test_android_sparse(work, src, expected):
    """Build an ext4 image, convert it to an Android sparse image with img2simg,
    then have moria unsparse it and extract the inner ext filesystem; compare the
    fs/ subtree. Needs `mke2fs` + `img2simg`. Returns failure count."""
    if not (have("mke2fs") and have("img2simg")):
        print("SKIP [android_sparse]: mke2fs or img2simg not installed")
        return 0
    raw = os.path.join(work, "sparse_raw.img")
    if subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-d", src, raw, "16M"],
                      capture_output=True).returncode != 0:
        print("SKIP [android_sparse]: mke2fs failed")
        return 0
    simg = os.path.join(work, "test.simg")
    if subprocess.run(["img2simg", raw, simg], capture_output=True).returncode != 0:
        print("SKIP [android_sparse]: img2simg failed")
        return 0
    outdir = os.path.join(work, "sparse.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, simg], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [android_sparse]: no extraction manifest\n{r.stdout[:200]}")
        return 1
    fs = os.path.join(outdir, entry["root"], "fs")
    got = {k: v for k, v in tree_manifest(fs).items() if not k.startswith("lost+found")}
    if got == expected:
        print(f"PASS [android_sparse]: unsparse + inner ext -> {entry['files']} files, "
              f"{entry['dirs']} dirs, {entry['symlinks']} symlinks")
        return 0
    print(f"FAIL [android_sparse]: missing={sorted(set(expected)-set(got))[:4]} "
          f"extra={sorted(set(got)-set(expected))[:4]} "
          f"mismatched={sorted(k for k in expected.keys()&got.keys() if expected[k]!=got[k])[:4]}")
    return 1


def test_erofs(work, src, expected):
    """Build EROFS images with mkfs.erofs and extract with moria, comparing every
    file byte-for-byte. Covers uncompressed (FLAT_PLAIN/FLAT_INLINE) plus the
    compressed-cluster paths: lz4 compact-index (default) and legacy full index,
    lz4 with tail-packing, deflate, and microlzma (compact index, legacy full
    index, and tail-packing), plus packed-inode fragments (tail fragments,
    all-fragments, and fragments+dedupe) and CHUNK_BASED files (chunk index /
    block array, with NULL_ADDR holes). Needs `mkfs.erofs` (erofs-utils).
    Returns failure count."""
    if not have("mkfs.erofs"):
        print("SKIP [erofs]: mkfs.erofs (erofs-utils) not installed")
        return 0
    variants = [
        ("uncompressed", []),
        ("lz4-compact", ["-zlz4"]),
        ("lz4-legacy", ["-zlz4", "-Elegacy-compress"]),
        ("lz4-tailpack", ["-zlz4", "-Eztailpacking"]),
        ("deflate", ["-zdeflate"]),
        ("lzma-compact", ["-zlzma"]),
        ("lzma-legacy", ["-zlzma", "-Elegacy-compress"]),
        ("lzma-tailpack", ["-zlzma", "-Eztailpacking"]),
        # packed-inode fragments: file tails (and, with -Eall-fragments, whole
        # files) live in the special packed inode. Also dedupe (shares identical
        # fragments) and a non-lz4 codec for the packed inode itself.
        ("lz4-fragments", ["-zlz4", "-Efragments"]),
        ("lz4-all-fragments", ["-zlz4", "-Eall-fragments"]),
        ("lz4-frag-dedupe", ["-zlz4", "-Efragments,dedupe"]),
        ("lzma-fragments", ["-zlzma", "-Efragments"]),
        # CHUNK_BASED files (layout 4): a per-inode chunk index/block array, with
        # NULL_ADDR holes for the sparse file in the fixture tree.
        ("chunk-4k", ["--chunksize=4096"]),
        ("chunk-64k", ["--chunksize=65536"]),
    ]
    failures = 0
    for label, opts in variants:
        img = os.path.join(work, f"test-{label}.erofs")
        # mkfs.erofs argument order is [opts] <image> <dir>
        r = subprocess.run(["mkfs.erofs", *opts, img, src], capture_output=True)
        if r.returncode != 0:
            print(f"SKIP [erofs/{label}]: mkfs.erofs {' '.join(opts)} unsupported")
            continue
        outdir = os.path.join(work, f"erofs-{label}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
        except Exception:
            print(f"FAIL [erofs/{label}]: no extraction manifest\n{r.stdout[:200]}")
            failures += 1
            continue
        got = tree_manifest(os.path.join(outdir, entry["root"]))
        if got == expected and entry["status"] == "ok":
            print(f"PASS [erofs/{label}]: {entry['files']} files, {entry['dirs']} dirs, "
                  f"{entry['symlinks']} symlinks")
        else:
            print(f"FAIL [erofs/{label}]: status={entry.get('status')} "
                  f"missing={sorted(set(expected)-set(got))[:4]} "
                  f"extra={sorted(set(got)-set(expected))[:4]} "
                  f"mismatched={sorted(k for k in expected.keys()&got.keys() if expected[k]!=got[k])[:4]}")
            failures += 1
    return failures


def test_ntfs(work, src, expected):
    """Build an NTFS image with mkntfs, populate it via a loop mount, then extract
    with moria and compare file content vs the mount. Needs mkntfs (ntfsprogs) +
    passwordless sudo mount. Skips otherwise. NTFS symlinks are reparse points
    (skipped). Returns failure count."""
    if not have("mkntfs"):
        print("SKIP [ntfs]: ntfsprogs (mkntfs) not installed")
        return 0
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        print("SKIP [ntfs]: passwordless sudo unavailable (needs mount to populate)")
        return 0
    img = os.path.join(work, "test.ntfs")
    with open(img, "wb") as f:
        f.truncate(48 * 1024 * 1024)
    if subprocess.run(["mkntfs", "-F", "-Q", img], capture_output=True).returncode != 0:
        print("SKIP [ntfs]: mkntfs failed")
        return 0
    mnt = os.path.join(work, "ntfs_mnt")
    os.makedirs(mnt, exist_ok=True)
    if subprocess.run(["sudo", "-n", "mount", "-o", "loop", img, mnt],
                      capture_output=True).returncode != 0:
        print("SKIP [ntfs]: mount failed")
        return 0
    ref = {}
    try:
        for name in os.listdir(src):
            subprocess.run(["sudo", "cp", "-r", os.path.join(src, name), mnt + "/"],
                           capture_output=True)
        subprocess.run(["sync"])
        # Reference = the mount's own file content (authoritative).
        for dp, dn, fn in os.walk(mnt):
            for x in fn:
                full = os.path.join(dp, x)
                rel = os.path.relpath(full, mnt)
                if rel.startswith("$") or os.path.islink(full):
                    continue
                try:
                    ref[rel] = hashlib.sha256(open(full, "rb").read()).hexdigest()
                except OSError:
                    pass
    finally:
        subprocess.run(["sudo", "-n", "umount", mnt], capture_output=True)
    outdir = os.path.join(work, "ntfs.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [ntfs]: no manifest\n{r.stdout[:200]}")
        return 1
    root = os.path.join(outdir, entry["root"])
    got = {k: v[1] for k, v in tree_manifest(root).items() if v[0] == "file"}
    if got == ref and entry["status"] == "ok":
        print(f"PASS [ntfs]: {entry['files']} files, {entry['dirs']} dirs")
        return 0
    print(f"FAIL [ntfs]: status={entry.get('status')} "
          f"missing={sorted(set(ref)-set(got))[:4]} extra={sorted(set(got)-set(ref))[:4]}")
    return 1


def test_uimage(work, src, expected):
    """Build U-Boot uImages (none/gzip/lzma) with mkimage and check moria's
    extracted payload matches the original kernel bytes. Needs mkimage. Returns
    failure count."""
    if not have("mkimage"):
        print("SKIP [uimage]: mkimage (uboot-tools) not installed")
        return 0
    kern = os.path.join(work, "kern.bin")
    with open(kern, "wb") as f:
        f.write(os.urandom(120000))
    want = open(kern, "rb").read()
    failures = 0
    ran = 0
    for comp in ("none", "gzip", "lzma"):
        payload = os.path.join(work, f"pl_{comp}")
        if comp == "none":
            shutil.copy(kern, payload)
        else:
            tool = {"gzip": ["gzip", "-c"], "lzma": ["lzma", "-c"]}[comp]
            if not have(tool[0]):
                continue
            with open(payload, "wb") as out:
                subprocess.run(tool, stdin=open(kern, "rb"), stdout=out, stderr=subprocess.DEVNULL)
        img = os.path.join(work, f"uImage.{comp}")
        if subprocess.run(["mkimage", "-A", "arm", "-O", "linux", "-T", "kernel", "-C", comp,
                           "-a", "0x8000", "-e", "0x8000", "-n", f"t-{comp}", "-d", payload, img],
                          capture_output=True).returncode != 0:
            continue
        ran += 1
        outdir = os.path.join(work, f"u_{comp}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
            got = open(os.path.join(outdir, entry["root"], "payload"), "rb").read()
        except Exception:
            print(f"FAIL [uimage/{comp}]: no payload\n{r.stdout[:200]}")
            failures += 1
            continue
        if got == want and entry["status"] == "ok":
            print(f"PASS [uimage/{comp}]: {len(got)} bytes")
        else:
            print(f"FAIL [uimage/{comp}]: status={entry.get('status')} match={got == want}")
            failures += 1
    if ran == 0:
        print("SKIP [uimage]: no usable compressors")
    return failures


def test_fit(work, src, expected):
    """Build U-Boot FIT (.itb) images with mkimage and check moria splits every
    subimage back to its original bytes. Covers embedded data, external data
    (-E: data-offset/data-size) and static-position data (-p: data-position), plus
    per-subimage decompression (none/gzip/lzma/lz4/zstd — the `data` is stored
    pre-compressed and the FIT only labels it). Needs mkimage + dtc. Returns
    failure count."""
    if not have("mkimage") or not have("dtc"):
        print("SKIP [fit]: mkimage/dtc (uboot-tools) not installed")
        return 0
    kern = os.path.join(work, "fk.bin")
    with open(kern, "wb") as f:
        f.write(b"KERNEL " + b"kdata " * 5000)  # compressible
    rd = os.path.join(work, "fr.bin")
    with open(rd, "wb") as f:
        f.write(os.urandom(4096))
    want_k = open(kern, "rb").read()
    want_r = open(rd, "rb").read()

    # Compressed copies of the kernel; the FIT `compression` prop labels them.
    comps = {"none": kern}
    for name, cmd in (("gzip", ["gzip", "-c"]), ("lzma", ["xz", "--format=lzma", "-c"]),
                      ("lz4", ["lz4", "-c"]), ("zstd", ["zstd", "-q", "-c"])):
        if not have(cmd[0]):
            continue
        p = os.path.join(work, f"fk.{name}")
        with open(p, "wb") as out:
            if subprocess.run(cmd, stdin=open(kern, "rb"), stdout=out,
                              stderr=subprocess.DEVNULL).returncode == 0 and os.path.getsize(p):
                comps[name] = p

    def its(kdata, kcomp):
        return f"""/dts-v1/;
/ {{ description = "moria fit test"; #address-cells = <1>;
  images {{
    kernel-1 {{ data = /incbin/("{kdata}"); type = "kernel"; arch = "arm"; os = "linux";
      compression = "{kcomp}"; load = <0x40008000>; entry = <0x40008000>;
      hash-1 {{ algo = "crc32"; }}; }};
    ramdisk-1 {{ data = /incbin/("{rd}"); type = "ramdisk"; arch = "arm"; os = "linux";
      compression = "none"; }};
  }};
  configurations {{ default = "conf-1"; conf-1 {{ kernel = "kernel-1"; ramdisk = "ramdisk-1"; }}; }};
}};
"""

    failures = 0
    # Layout variants (kernel stored uncompressed).
    layouts = [("embedded", []), ("external", ["-E"]), ("position", ["-E", "-p", "0x2000"])]
    cases = [(f"layout-{name}", opts, "none", kern) for name, opts in layouts]
    # Compression variants (embedded layout).
    cases += [(f"comp-{c}", [], c, comps[c]) for c in comps]

    for label, opts, kcomp, kdata in cases:
        itsf = os.path.join(work, f"fit-{label}.its")
        with open(itsf, "w") as f:
            f.write(its(kdata, kcomp))
        img = os.path.join(work, f"fit-{label}.itb")
        if subprocess.run(["mkimage", *opts, "-f", itsf, img], capture_output=True).returncode != 0:
            print(f"SKIP [fit/{label}]: mkimage {' '.join(opts)} unsupported")
            continue
        outdir = os.path.join(work, f"fit-{label}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
            base = os.path.join(outdir, entry["root"])
            got_k = open(os.path.join(base, "kernel-1"), "rb").read()
            got_r = open(os.path.join(base, "ramdisk-1"), "rb").read()
        except Exception:
            print(f"FAIL [fit/{label}]: no subimages\n{r.stdout[:200]}")
            failures += 1
            continue
        if got_k == want_k and got_r == want_r and entry["status"] == "ok" and entry["type"] == "fit":
            print(f"PASS [fit/{label}]: {entry['files']} subimages")
        else:
            print(f"FAIL [fit/{label}]: status={entry.get('status')} type={entry.get('type')} "
                  f"kernel={got_k == want_k} ramdisk={got_r == want_r}")
            failures += 1
    return failures


def test_recursive(work, src, expected):
    """Nested containers must unpack recursively by default: build a gzip-wrapped
    squashfs (2 levels) and a squashfs holding a .tar.gz (3 levels), extract with
    moria, and confirm the deepest files come out and the manifest depths are
    right. Also check --depth 1 stops at one level. Needs mksquashfs + gzip + tar.
    Returns failure count."""
    if not have("mksquashfs") or not have("gzip") or not have("tar"):
        print("SKIP [recursive]: mksquashfs/gzip/tar not all installed")
        return 0
    failures = 0
    # --- 2 levels: gzip(squashfs) ---
    sq = os.path.join(work, "rec_inner.sqfs")
    if subprocess.run(["mksquashfs", src, sq, "-noappend", "-no-progress"],
                      capture_output=True).returncode != 0:
        print("SKIP [recursive]: mksquashfs failed")
        return 0
    gz = os.path.join(work, "rec_wrapped.gz")
    with open(gz, "wb") as o:
        subprocess.run(["gzip", "-c", sq], stdout=o, stderr=subprocess.DEVNULL)
    outdir = os.path.join(work, "rec2.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, gz], capture_output=True)
    try:
        ents = json.loads(r.stdout.decode())["extraction"]["extracted"]
    except Exception:
        print(f"FAIL [recursive/2level]: no manifest\n{r.stdout[:200]}")
        return failures + 1
    types = {(e["type"], e["depth"]) for e in ents}
    # find a known file from `src` somewhere under the squashfs child extraction
    want_names = {os.path.basename(p) for p in expected}
    got = {os.path.basename(p) for p in glob_files(outdir)}
    if ("gzip", 1) in types and ("squashfs", 2) in types and want_names & got:
        print(f"PASS [recursive/2level]: gzip@d1 -> squashfs@d2, {len(ents)} entries")
    else:
        print(f"FAIL [recursive/2level]: types={sorted(types)} names_recovered={bool(want_names & got)}")
        failures += 1

    # --- --depth 1 stops at the wrapper ---
    outdir1 = os.path.join(work, "rec1.out")
    r = subprocess.run([MORIA, "-j", "--extract", "--depth", "1", "-C", outdir1, gz], capture_output=True)
    try:
        ents1 = json.loads(r.stdout.decode())["extraction"]["extracted"]
        if [e["type"] for e in ents1] == ["gzip"]:
            print("PASS [recursive/depth1]: recursion off -> only the gzip layer")
        else:
            print(f"FAIL [recursive/depth1]: {[e['type'] for e in ents1]}")
            failures += 1
    except Exception:
        print("FAIL [recursive/depth1]: no manifest")
        failures += 1

    # --- 3 levels: squashfs containing archive.tar.gz ---
    d3 = os.path.join(work, "rec3src", "lib")
    os.makedirs(d3, exist_ok=True)
    leaf = os.path.join(work, "rec3_leaf.txt")
    with open(leaf, "w") as f:
        f.write("deepest recursive payload\n")
    tarf = os.path.join(work, "rec3_inner.tar")
    subprocess.run(["tar", "-C", os.path.dirname(leaf), "-cf", tarf, os.path.basename(leaf)],
                   capture_output=True)
    with open(os.path.join(d3, "archive.tar.gz"), "wb") as o:
        subprocess.run(["gzip", "-c", tarf], stdout=o, stderr=subprocess.DEVNULL)
    sq3 = os.path.join(work, "rec3.sqfs")
    subprocess.run(["mksquashfs", os.path.join(work, "rec3src"), sq3, "-noappend", "-no-progress"],
                   capture_output=True)
    outdir3 = os.path.join(work, "rec3.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir3, sq3], capture_output=True)
    try:
        ents3 = json.loads(r.stdout.decode())["extraction"]["extracted"]
        depths = {e["type"]: e["depth"] for e in ents3}
        recovered = any(open(p, "rb").read() == b"deepest recursive payload\n"
                        for p in glob_files(outdir3) if os.path.basename(p) == "rec3_leaf.txt")
        if depths.get("squashfs") == 1 and depths.get("gzip") == 2 and depths.get("tar") == 3 and recovered:
            print("PASS [recursive/3level]: squashfs@d1 -> gzip@d2 -> tar@d3, leaf recovered")
        else:
            print(f"FAIL [recursive/3level]: depths={depths} leaf_recovered={recovered}")
            failures += 1
    except Exception as ex:
        print(f"FAIL [recursive/3level]: {ex}")
        failures += 1
    return failures


def glob_files(root):
    """Every regular file under root except manifest.json."""
    out = []
    for dirpath, _, names in os.walk(root):
        for n in names:
            if n != "manifest.json":
                out.append(os.path.join(dirpath, n))
    return out


def test_exfat(work, src, expected):
    """Build an exFAT image with mkfs.exfat, populate it via a loop mount, then
    extract with moria and compare file content. Needs mkfs.exfat + passwordless
    sudo mount (exFAT has no offline populate tool). Skips otherwise. exFAT has no
    unix modes/symlinks. Returns failure count."""
    if not have("mkfs.exfat"):
        print("SKIP [exfat]: exfatprogs (mkfs.exfat) not installed")
        return 0
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        print("SKIP [exfat]: passwordless sudo unavailable (needs mount to populate)")
        return 0
    img = os.path.join(work, "test.exfat")
    with open(img, "wb") as f:
        f.truncate(48 * 1024 * 1024)
    if subprocess.run(["mkfs.exfat", img], capture_output=True).returncode != 0:
        print("SKIP [exfat]: mkfs.exfat failed")
        return 0
    mnt = os.path.join(work, "exfat_mnt")
    os.makedirs(mnt, exist_ok=True)
    if subprocess.run(["sudo", "-n", "mount", "-o", "loop", img, mnt],
                      capture_output=True).returncode != 0:
        print("SKIP [exfat]: mount failed")
        return 0
    try:
        for name in os.listdir(src):
            subprocess.run(["sudo", "cp", "-r", os.path.join(src, name), mnt + "/"],
                           capture_output=True)
        subprocess.run(["sync"])
    finally:
        subprocess.run(["sudo", "-n", "umount", mnt], capture_output=True)
    links = {k for k, v in expected.items() if v[0] == "link"}
    exp_files = {k: v for k, v in expected.items() if v[0] == "file" and k not in links}
    outdir = os.path.join(work, "exfat.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [exfat]: no manifest\n{r.stdout[:200]}")
        return 1
    got = {k: v for k, v in tree_manifest(os.path.join(outdir, entry["root"])).items()
           if v[0] == "file" and k not in links}
    if got == exp_files and entry["status"] == "ok":
        print(f"PASS [exfat]: {entry['files']} files, {entry['dirs']} dirs")
        return 0
    print(f"FAIL [exfat]: status={entry.get('status')} "
          f"missing={sorted(set(exp_files)-set(got))[:4]} extra={sorted(set(got)-set(exp_files))[:4]}")
    return 1


def test_compressed(work, src, expected):
    """Wrap a known payload in gzip/xz/zstd/lz4 and check moria's streaming
    extractor decompresses it byte-identical. Uses whichever CLI compressors are
    present. Returns failure count."""
    payload = os.path.join(work, "payload.bin")
    with open(payload, "wb") as f:
        f.write(os.urandom(200000))
    with open(payload, "rb") as f:
        want = f.read()
    cases = [("gzip", "gzip", ["gzip", "-c"]), ("xz", "xz", ["xz", "-c"]),
             ("zstd", "zstd", ["zstd", "-q", "-c"]), ("lz4", "lz4", ["lz4", "-q", "-c"]),
             ("lz4-legacy", "lz4", ["lz4", "-l", "-q", "-c"])]  # -l = legacy frame
    failures = 0
    ran = 0
    for label, tool, cmd in cases:
        if not have(tool):
            continue
        img = os.path.join(work, f"w.{label}")
        with open(img, "wb") as out:
            if subprocess.run(cmd, stdin=open(payload, "rb"), stdout=out,
                              stderr=subprocess.DEVNULL).returncode != 0:
                continue
        ran += 1
        outdir = os.path.join(work, f"c_{label}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
            got = open(os.path.join(outdir, entry["root"], "decompressed"), "rb").read()
        except Exception:
            print(f"FAIL [compressed/{label}]: no output\n{r.stdout[:200]}")
            failures += 1
            continue
        if got == want and entry["status"] == "ok":
            print(f"PASS [compressed/{label}]: {len(got)} bytes")
        else:
            print(f"FAIL [compressed/{label}]: status={entry.get('status')} match={got == want}")
            failures += 1
    if ran == 0:
        print("SKIP [compressed]: no CLI compressors present")
    return failures


def test_iso9660(work, src, expected):
    """Build a Rock Ridge ISO with xorriso and extract with moria, comparing
    byte-for-byte (RR preserves long names + symlinks). Needs xorriso. Returns
    failure count."""
    if not have("xorriso"):
        print("SKIP [iso9660]: xorriso not installed")
        return 0
    img = os.path.join(work, "test.iso")
    if subprocess.run(["xorriso", "-as", "mkisofs", "-R", "-o", img, src],
                      capture_output=True).returncode != 0:
        print("SKIP [iso9660]: xorriso failed")
        return 0
    outdir = os.path.join(work, "iso.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [iso9660]: no manifest\n{r.stdout[:200]}")
        return 1
    got = tree_manifest(os.path.join(outdir, entry["root"]))
    if got == expected and entry["status"] == "ok":
        print(f"PASS [iso9660]: {entry['files']} files, {entry['dirs']} dirs, {entry['symlinks']} symlinks")
        return 0
    print(f"FAIL [iso9660]: status={entry.get('status')} "
          f"missing={sorted(set(expected)-set(got))[:4]} extra={sorted(set(got)-set(expected))[:4]} "
          f"mismatched={sorted(k for k in expected.keys()&got.keys() if expected[k]!=got[k])[:4]}")
    return 1


def test_fat(work, src, expected):
    """Build FAT12/16/32 images with mkfs.fat + mcopy and extract with moria,
    comparing every file byte-for-byte. Needs dosfstools + mtools. FAT stores no
    unix modes/symlinks, so we compare file content only (symlinks are skipped in
    the source set). Returns failure count."""
    if not (have("mkfs.fat") and have("mcopy")):
        print("SKIP [fat]: dosfstools/mtools (mkfs.fat / mcopy) not installed")
        return 0
    # File content only. FAT can't store symlinks; mcopy turns them into regular
    # files, so drop the symlink names from the comparison entirely.
    links = {k for k, v in expected.items() if v[0] == "link"}
    exp_files = {k: v for k, v in expected.items() if v[0] == "file" and k not in links}
    failures = 0
    for typ, size_mb in ((12, 4), (16, 40), (32, 66)):
        img = os.path.join(work, f"fat{typ}.img")
        with open(img, "wb") as f:
            f.truncate(size_mb * 1024 * 1024)
        if subprocess.run(["mkfs.fat", "-F", str(typ), img], capture_output=True).returncode != 0:
            print(f"SKIP [fat{typ}]: mkfs.fat failed")
            continue
        # mcopy each top-level entry recursively into the image root.
        for name in os.listdir(src):
            subprocess.run(["mcopy", "-s", "-i", img, os.path.join(src, name), "::"],
                           capture_output=True)
        outdir = os.path.join(work, f"fat{typ}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
        except Exception:
            print(f"FAIL [fat{typ}]: no manifest\n{r.stdout[:200]}")
            failures += 1
            continue
        got = {k: v for k, v in tree_manifest(os.path.join(outdir, entry["root"])).items()
               if v[0] == "file" and k not in links}
        if got == exp_files and entry["status"] == "ok":
            print(f"PASS [fat{typ}]: {entry['files']} files, {entry['dirs']} dirs")
        else:
            print(f"FAIL [fat{typ}]: status={entry.get('status')} "
                  f"missing={sorted(set(exp_files)-set(got))[:4]} "
                  f"extra={sorted(set(got)-set(exp_files))[:4]} "
                  f"mismatched={sorted(k for k in exp_files.keys()&got.keys() if exp_files[k]!=got[k])[:4]}")
            failures += 1
    return failures


def test_android_boot(work, src, expected):
    """Build Android boot images (header v0-v4) with mkbootimg and check moria
    splits each component byte-identical to the input files. Needs mkbootimg.
    Returns failure count."""
    if not have("mkbootimg"):
        print("SKIP [android_boot]: mkbootimg not installed")
        return 0
    kern = os.path.join(work, "k.bin")
    rd = os.path.join(work, "r.bin")
    with open(kern, "wb") as f:
        f.write(os.urandom(120000))
    with open(rd, "wb") as f:
        f.write(os.urandom(50000))
    inputs = {"kernel": kern, "ramdisk": rd}
    failures = 0
    for v in (0, 1, 2, 3, 4):
        img = os.path.join(work, f"boot{v}.img")
        args = ["mkbootimg", "--kernel", kern, "--ramdisk", rd, "--header_version", str(v), "-o", img]
        if v <= 2:
            args += ["--pagesize", "2048"]
        if v == 2:
            args += ["--dtb", rd]  # v2 requires a dtb
        if subprocess.run(args, capture_output=True).returncode != 0:
            print(f"SKIP [android_boot/v{v}]: mkbootimg failed")
            continue
        outdir = os.path.join(work, f"boot{v}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
        except Exception:
            print(f"FAIL [android_boot/v{v}]: no manifest\n{r.stdout[:200]}")
            failures += 1
            continue
        root = os.path.join(outdir, entry["root"])
        ok = entry["status"] == "ok"
        for name, path in inputs.items():
            got = os.path.join(root, name)
            if not os.path.exists(got) or open(got, "rb").read() != open(path, "rb").read():
                ok = False
        if ok:
            print(f"PASS [android_boot/v{v}]: {entry['files']} components")
        else:
            print(f"FAIL [android_boot/v{v}]: status={entry.get('status')}")
            failures += 1
    return failures


def test_zip(work, src, expected):
    """Build a ZIP with `zip` and extract with moria, comparing byte-for-byte.
    Covers stored + deflated members and symlinks. Returns failure count."""
    if not have("zip"):
        print("SKIP [zip]: zip not installed")
        return 0
    img = os.path.join(work, "test.zip")
    # -y stores symlinks as symlinks; -r recurses.
    if subprocess.run(["zip", "-q", "-r", "-y", img, "."], cwd=src,
                      capture_output=True).returncode != 0:
        print("SKIP [zip]: zip failed")
        return 0
    outdir = os.path.join(work, "zip.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [zip]: no extraction manifest\n{r.stdout[:200]}")
        return 1
    got = tree_manifest(os.path.join(outdir, entry["root"]))
    if got == expected and entry["status"] == "ok":
        print(f"PASS [zip]: {entry['files']} files, {entry['dirs']} dirs, {entry['symlinks']} symlinks")
        return 0
    print(f"FAIL [zip]: status={entry.get('status')} "
          f"missing={sorted(set(expected)-set(got))[:4]} extra={sorted(set(got)-set(expected))[:4]} "
          f"mismatched={sorted(k for k in expected.keys()&got.keys() if expected[k]!=got[k])[:4]}")
    return 1


def test_f2fs(work, src, expected):
    """Build F2FS images with mkfs.f2fs + sload.f2fs and extract with moria,
    comparing every file byte-for-byte. Covers the default layout, the
    extra_attr / flexible_inline_xattr feature set (Android's), and per-file
    compression (F2FS_COMPR_FL clusters: zeros.dat compresses, rand.bin stays raw
    in the same compressed inode). Needs f2fs-tools (mkfs.f2fs, sload.f2fs).
    Returns failure count. (LZO/ZSTD and the compacted-summary NAT journal are
    validated out-of-band against kernel-written images; sload here builds LZ4.)"""
    if not (have("mkfs.f2fs") and have("sload.f2fs")):
        print("SKIP [f2fs]: f2fs-tools (mkfs.f2fs / sload.f2fs) not installed")
        return 0
    # (label, mkfs -O opts, extra sload opts)
    variants = [
        ("default", [], []),
        ("extra_attr", ["-O", "extra_attr"], []),
        ("android", ["-O", "extra_attr,inode_checksum,flexible_inline_xattr"], []),
        ("compress-lz4", ["-O", "extra_attr,compression"], ["-c", "-a", "lz4", "-L", "2"]),
    ]
    failures = 0
    for label, opts, sload_opts in variants:
        img = os.path.join(work, f"test-f2fs-{label}.img")
        with open(img, "wb") as f:
            f.truncate(128 * 1024 * 1024)  # f2fs needs a minimum-sized device
        if subprocess.run(["mkfs.f2fs", "-f", *opts, img], capture_output=True).returncode != 0:
            print(f"SKIP [f2fs/{label}]: mkfs.f2fs {' '.join(opts)} unsupported")
            continue
        if subprocess.run(["sload.f2fs", "-f", src, *sload_opts, img],
                          capture_output=True).returncode != 0:
            print(f"SKIP [f2fs/{label}]: sload.f2fs failed")
            continue
        outdir = os.path.join(work, f"f2fs-{label}.out")
        r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
        try:
            entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
        except Exception:
            print(f"FAIL [f2fs/{label}]: no extraction manifest\n{r.stdout[:200]}")
            failures += 1
            continue
        got = tree_manifest(os.path.join(outdir, entry["root"]))
        if got == expected and entry["status"] == "ok":
            print(f"PASS [f2fs/{label}]: {entry['files']} files, {entry['dirs']} dirs, "
                  f"{entry['symlinks']} symlinks")
        else:
            print(f"FAIL [f2fs/{label}]: status={entry.get('status')} "
                  f"missing={sorted(set(expected)-set(got))[:4]} "
                  f"extra={sorted(set(got)-set(expected))[:4]} "
                  f"mismatched={sorted(k for k in expected.keys()&got.keys() if expected[k]!=got[k])[:4]}")
            failures += 1
    return failures


def test_hfsplus(work, src, expected):
    """Build an HFS+ image with mkfs.hfsplus, populate it via a loop mount, then
    extract with moria and compare file content + symlink targets vs the mount
    (authoritative reference). Needs mkfs.hfsplus (hfsprogs) + passwordless sudo
    mount. Skips otherwise. Returns failure count."""
    if not have("mkfs.hfsplus"):
        print("SKIP [hfsplus]: hfsprogs (mkfs.hfsplus) not installed")
        return 0
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        print("SKIP [hfsplus]: passwordless sudo unavailable (needs mount to populate)")
        return 0
    img = os.path.join(work, "test.hfsplus")
    with open(img, "wb") as f:
        f.truncate(48 * 1024 * 1024)
    if subprocess.run(["mkfs.hfsplus", "-v", "MoriaTest", img],
                      capture_output=True).returncode != 0:
        print("SKIP [hfsplus]: mkfs.hfsplus failed")
        return 0
    mnt = os.path.join(work, "hfs_mnt")
    os.makedirs(mnt, exist_ok=True)
    if subprocess.run(["sudo", "-n", "mount", "-t", "hfsplus", "-o", "loop", img, mnt],
                      capture_output=True).returncode != 0:
        print("SKIP [hfsplus]: mount failed")
        return 0
    ref = {}
    try:
        for name in os.listdir(src):
            subprocess.run(["sudo", "cp", "-a", os.path.join(src, name), mnt + "/"],
                           capture_output=True)
        subprocess.run(["sync"])
        for dp, dn, fn in os.walk(mnt):
            for x in fn:
                full = os.path.join(dp, x)
                rel = os.path.relpath(full, mnt)
                if os.path.islink(full):
                    ref[rel] = ("link", os.readlink(full))
                else:
                    try:
                        ref[rel] = ("file", hashlib.sha256(open(full, "rb").read()).hexdigest())
                    except OSError:
                        pass
    finally:
        subprocess.run(["sudo", "-n", "umount", mnt], capture_output=True)
    outdir = os.path.join(work, "hfsplus.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [hfsplus]: no manifest\n{r.stdout[:200]}")
        return 1
    root = os.path.join(outdir, entry["root"])
    got = {k: v for k, v in tree_manifest(root).items() if v[0] != "dir"}
    if got == ref and entry["status"] == "ok":
        print(f"PASS [hfsplus]: {entry['files']} files, {entry['dirs']} dirs, "
              f"{entry['symlinks']} symlinks")
        return 0
    miss = sorted(set(ref) - set(got))[:4]
    mism = sorted(k for k in ref.keys() & got.keys() if ref[k] != got[k])[:4]
    print(f"FAIL [hfsplus]: status={entry.get('status')} missing={miss} mismatched={mism}")
    return 1


def test_xfs(work, src, expected):
    """Build an XFS image with mkfs.xfs, populate it via a loop mount, then extract
    with moria and compare file content + symlink targets vs the mount. Needs
    mkfs.xfs (xfsprogs) + passwordless sudo mount. Skips otherwise. Returns failure
    count."""
    if not have("mkfs.xfs"):
        print("SKIP [xfs]: xfsprogs (mkfs.xfs) not installed")
        return 0
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        print("SKIP [xfs]: passwordless sudo unavailable (needs mount to populate)")
        return 0
    img = os.path.join(work, "test.xfs")
    with open(img, "wb") as f:
        f.truncate(300 * 1024 * 1024)  # xfs needs a minimum-sized device
    if subprocess.run(["mkfs.xfs", "-q", "-f", img], capture_output=True).returncode != 0:
        print("SKIP [xfs]: mkfs.xfs failed")
        return 0
    mnt = os.path.join(work, "xfs_mnt")
    os.makedirs(mnt, exist_ok=True)
    if subprocess.run(["sudo", "-n", "mount", "-t", "xfs", "-o", "loop", img, mnt],
                      capture_output=True).returncode != 0:
        print("SKIP [xfs]: mount failed")
        return 0
    ref = {}
    try:
        for name in os.listdir(src):
            subprocess.run(["sudo", "cp", "-a", os.path.join(src, name), mnt + "/"],
                           capture_output=True)
        subprocess.run(["sync"])
        for dp, dn, fn in os.walk(mnt):
            for x in fn:
                full = os.path.join(dp, x)
                rel = os.path.relpath(full, mnt)
                if os.path.islink(full):
                    ref[rel] = ("link", os.readlink(full))
                else:
                    try:
                        ref[rel] = ("file", hashlib.sha256(open(full, "rb").read()).hexdigest())
                    except OSError:
                        pass
    finally:
        subprocess.run(["sudo", "-n", "umount", mnt], capture_output=True)
    outdir = os.path.join(work, "xfs.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [xfs]: no manifest\n{r.stdout[:200]}")
        return 1
    root = os.path.join(outdir, entry["root"])
    got = {k: v for k, v in tree_manifest(root).items() if v[0] != "dir"}
    if got == ref and entry["status"] == "ok":
        print(f"PASS [xfs]: {entry['files']} files, {entry['dirs']} dirs, "
              f"{entry['symlinks']} symlinks")
        return 0
    miss = sorted(set(ref) - set(got))[:4]
    mism = sorted(k for k in ref.keys() & got.keys() if ref[k] != got[k])[:4]
    print(f"FAIL [xfs]: status={entry.get('status')} missing={miss} mismatched={mism}")
    return 1


def test_btrfs(work, src, expected):
    """Build a btrfs image with mkfs.btrfs, populate it via a loop mount with zstd
    compression (to exercise compressed extents), then extract with moria and
    compare file content + symlink targets vs the mount. Needs mkfs.btrfs
    (btrfs-progs) + passwordless sudo mount. Skips otherwise. Returns failure
    count."""
    if not have("mkfs.btrfs"):
        print("SKIP [btrfs]: btrfs-progs (mkfs.btrfs) not installed")
        return 0
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        print("SKIP [btrfs]: passwordless sudo unavailable (needs mount to populate)")
        return 0
    img = os.path.join(work, "test.btrfs")
    with open(img, "wb") as f:
        f.truncate(300 * 1024 * 1024)  # btrfs needs a minimum-sized device
    if subprocess.run(["mkfs.btrfs", "-q", "-f", img], capture_output=True).returncode != 0:
        print("SKIP [btrfs]: mkfs.btrfs failed")
        return 0
    mnt = os.path.join(work, "btrfs_mnt")
    os.makedirs(mnt, exist_ok=True)
    if subprocess.run(["sudo", "-n", "mount", "-o", "loop,compress=zstd", img, mnt],
                      capture_output=True).returncode != 0:
        print("SKIP [btrfs]: mount failed")
        return 0
    ref = {}
    try:
        for name in os.listdir(src):
            subprocess.run(["sudo", "cp", "-a", os.path.join(src, name), mnt + "/"],
                           capture_output=True)
        # A subvolume (with content) and a snapshot of it, to exercise the
        # subvolume-recursion path. Best-effort: ignored if `btrfs` is unavailable.
        if have("btrfs"):
            subprocess.run(["sudo", "btrfs", "subvolume", "create", mnt + "/subvol"],
                           capture_output=True)
            subprocess.run(["sudo", "cp", "-a", os.path.join(src, "etc"), mnt + "/subvol/"],
                           capture_output=True)
            subprocess.run(["sudo", "btrfs", "subvolume", "snapshot", mnt + "/subvol",
                            mnt + "/snap"], capture_output=True)
        subprocess.run(["sync"])
        for dp, dn, fn in os.walk(mnt):
            for x in fn:
                full = os.path.join(dp, x)
                rel = os.path.relpath(full, mnt)
                if os.path.islink(full):
                    ref[rel] = ("link", os.readlink(full))
                else:
                    try:
                        ref[rel] = ("file", hashlib.sha256(open(full, "rb").read()).hexdigest())
                    except OSError:
                        pass
    finally:
        subprocess.run(["sudo", "-n", "umount", mnt], capture_output=True)
    outdir = os.path.join(work, "btrfs.out")
    r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
    try:
        entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
    except Exception:
        print(f"FAIL [btrfs]: no manifest\n{r.stdout[:200]}")
        return 1
    root = os.path.join(outdir, entry["root"])
    got = {k: v for k, v in tree_manifest(root).items() if v[0] != "dir"}
    if got == ref and entry["status"] == "ok":
        print(f"PASS [btrfs]: {entry['files']} files, {entry['dirs']} dirs, "
              f"{entry['symlinks']} symlinks")
        return 0
    miss = sorted(set(ref) - set(got))[:4]
    mism = sorted(k for k in ref.keys() & got.keys() if ref[k] != got[k])[:4]
    print(f"FAIL [btrfs]: status={entry.get('status')} missing={miss} mismatched={mism}")
    return 1


def build_squashfs(be, compress):
    """Hand-build a minimal, valid SquashFS v4 (LE or BE, raw or gzip) with the
    tree /file1="hello\\n", /sub/file2="world!\\n". No mksquashfs needed; the point
    is big-endian ("sqsh") images, which no tool can create."""
    import struct
    import zlib
    E = ">" if be else "<"
    u16 = lambda v: struct.pack(E + "H", v)
    i16 = lambda v: struct.pack(E + "h", v)
    u32 = lambda v: struct.pack(E + "I", v)
    u64 = lambda v: struct.pack(E + "Q", v)
    BLOCK, BLOCK_LOG, UNCOMP_BLOCK, META_UNCOMP = 131072, 17, 1 << 24, 0x8000

    def meta(p):
        if compress:
            z = zlib.compress(p, 9)
            return u16(len(z)) + z
        return u16(META_UNCOMP | len(p)) + p

    def datablock(p):
        if compress:
            z = zlib.compress(p, 9)
            return z, len(z)
        return p, UNCOMP_BLOCK | len(p)

    common = lambda t, m, ino: u16(t) + u16(m) + u16(0) + u16(0) + u32(0) + u32(ino)
    file_inode = lambda ino, start, dlen, sf: (
        common(2, 0o644, ino) + u32(start) + u32(0xFFFFFFFF) + u32(0) + u32(dlen) + u32(sf))
    dir_inode = lambda ino, sb_, off, llen, par: (
        common(1, 0o755, ino) + u32(sb_) + u32(2) + u16(llen + 3) + u16(off) + u32(par))

    f1, f2 = b"hello\n", b"world!\n"
    f1_disk, f1_sf = datablock(f1)
    f2_disk, f2_sf = datablock(f2)
    blob = bytearray(96)
    f1_start = len(blob); blob += f1_disk
    f2_start = len(blob); blob += f2_disk

    DIR_SZ, FILE_SZ = 32, 36
    off_root, off_sub = 0, 32
    off_file1, off_file2 = off_sub + DIR_SZ, off_sub + DIR_SZ + FILE_SZ

    def entry(coff, name, t):
        return u16(coff) + i16(0) + u16(t) + u16(len(name) - 1) + name.encode()
    hdr = lambda cm1, sb_, base: u32(cm1) + u32(sb_) + u32(base)
    root_listing = hdr(1, 0, 1) + entry(off_file1, "file1", 2) + entry(off_sub, "sub", 1)
    sub_listing = hdr(0, 0, 1) + entry(off_file2, "file2", 2)

    inode_payload = (dir_inode(1, 0, 0, len(root_listing), 5) +
                     dir_inode(2, 0, len(root_listing), len(sub_listing), 1) +
                     file_inode(3, f1_start, len(f1), f1_sf) +
                     file_inode(4, f2_start, len(f2), f2_sf))
    inode_table_start = len(blob); blob += meta(inode_payload)
    directory_table_start = len(blob); blob += meta(root_listing + sub_listing)
    id_meta_off = len(blob); blob += meta(u32(0))
    id_table_start = len(blob); blob += u64(id_meta_off)
    bytes_used = len(blob)

    sb = (b"sqsh" if be else b"hsqs") + u32(4) + u32(0) + u32(BLOCK) + u32(0) + u16(1) + \
        u16(BLOCK_LOG) + u16(0) + u16(1) + u16(4) + u16(0) + u64(off_root) + u64(bytes_used) + \
        u64(id_table_start) + u64(0xFFFFFFFFFFFFFFFF) + u64(inode_table_start) + \
        u64(directory_table_start) + u64(0xFFFFFFFFFFFFFFFF) + u64(0xFFFFFFFFFFFFFFFF)
    assert len(sb) == 96, len(sb)
    blob[0:96] = sb
    return bytes(blob)


def test_squashfs_endian(work):
    """Endian-aware squashfs: LE ("hsqs") and BE ("sqsh"), raw and gzip. BE images
    are the ones no tool creates; moria must parse every field big-endian."""
    failures = 0
    for be in (False, True):
        for comp in (False, True):
            label = ("BE" if be else "LE") + ("/gzip" if comp else "/raw")
            img = os.path.join(work, f"sq_{label.replace('/', '_')}.bin")
            with open(img, "wb") as fh:
                fh.write(build_squashfs(be, comp))
            outdir = os.path.join(work, f"sq_{label.replace('/', '_')}.out")
            r = subprocess.run([MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True)
            try:
                entry = json.loads(r.stdout.decode())["extraction"]["extracted"][0]
            except Exception:
                print(f"FAIL [squashfs {label}]: no extraction manifest\n{r.stdout[:200]}")
                failures += 1
                continue
            root = os.path.join(outdir, entry["root"])
            try:
                got1 = open(os.path.join(root, "file1"), "rb").read()
                got2 = open(os.path.join(root, "sub", "file2"), "rb").read()
            except OSError as e:
                print(f"FAIL [squashfs {label}]: missing file ({e})")
                failures += 1
                continue
            if entry["status"] == "ok" and got1 == b"hello\n" and got2 == b"world!\n":
                print(f"PASS [squashfs {label}]: file1 + sub/file2 recovered")
            else:
                print(f"FAIL [squashfs {label}]: status={entry['status']} "
                      f"file1={got1!r} file2={got2!r}")
                failures += 1
    return failures


def main():
    if not os.path.exists(MORIA):
        print("SKIP: moria binary not built")
        return 0

    work = tempfile.mkdtemp(prefix="moria-xt-")
    try:
        src = os.path.join(work, "tree")
        build_tree(src)
        expected = tree_manifest(src)

        failures = 0
        failures += test_cpio(work, src, expected)
        failures += test_ext(work, src, expected)
        failures += test_jffs2(work, src, expected)
        failures += test_ubifs(work, src, expected)
        failures += test_tar(work, src, expected)
        failures += test_romfs(work, src, expected)
        failures += test_yaffs2(work, src, expected)
        failures += test_yaffs2_embedded(work, src)
        failures += test_yaffs2_dataonly(work, src)
        failures += test_yaffs2_extra_header(work)
        failures += test_yaffs2_sparse(work)
        failures += test_verity(work)
        failures += test_cramfs(work, src, expected)
        failures += test_android_sparse(work, src, expected)
        failures += test_erofs(work, src, expected)
        failures += test_f2fs(work, src, expected)
        failures += test_zip(work, src, expected)
        failures += test_android_boot(work, src, expected)
        failures += test_fat(work, src, expected)
        failures += test_exfat(work, src, expected)
        failures += test_uimage(work, src, expected)
        failures += test_fit(work, src, expected)
        failures += test_recursive(work, src, expected)
        failures += test_ntfs(work, src, expected)
        failures += test_hfsplus(work, src, expected)
        failures += test_xfs(work, src, expected)
        failures += test_btrfs(work, src, expected)
        failures += test_iso9660(work, src, expected)
        failures += test_compressed(work, src, expected)
        failures += test_squashfs_endian(work)

        if not have("mksquashfs"):
            print("SKIP [squashfs]: mksquashfs (squashfs-tools) not installed")
            print("-" * 60)
            return 1 if failures else 0

        for comp in COMPRESSORS:
            img = os.path.join(work, f"{comp}.sqfs")
            r = subprocess.run(
                ["mksquashfs", src, img, "-comp", comp, "-noappend", "-no-progress"],
                capture_output=True,
            )
            if r.returncode != 0:
                print(f"SKIP [{comp}]: mksquashfs failed (compressor unsupported?)")
                continue

            outdir = os.path.join(work, f"{comp}.out")
            r = subprocess.run(
                [MORIA, "-j", "--extract", "-C", outdir, img], capture_output=True
            )
            try:
                doc = json.loads(r.stdout.decode())
                entry = doc["extraction"]["extracted"][0]
            except Exception:
                print(f"FAIL [{comp}]: no extraction manifest\n{r.stdout[:200]}")
                failures += 1
                continue
            if entry["status"] != "ok":
                print(f"FAIL [{comp}]: status={entry['status']}")
                failures += 1
                continue

            sub = os.path.join(outdir, entry["root"])
            got = tree_manifest(sub)
            if got == expected:
                print(f"PASS [{comp}]: {entry['files']} files, {entry['symlinks']} symlinks")
            else:
                failures += 1
                only_exp = set(expected) - set(got)
                only_got = set(got) - set(expected)
                mism = {k for k in expected.keys() & got.keys() if expected[k] != got[k]}
                print(f"FAIL [{comp}]: missing={sorted(only_exp)} "
                      f"extra={sorted(only_got)} mismatched={sorted(mism)}")

        print("-" * 60)
        if failures:
            print(f"FAIL: {failures} extraction case(s) mismatched")
            return 1
        print("PASS: cpio+ext+jffs2+ubifs+tar+romfs+yaffs2+cramfs+android_sparse+android_boot+erofs+f2fs+zip+fat+exfat+iso9660+compressed+uimage+fit+ntfs+hfsplus+xfs+btrfs+squashfs round-trip")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

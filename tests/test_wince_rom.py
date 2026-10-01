#!/usr/bin/env python3
"""Windows CE XIP ROM identify + extract regression.

Builds a synthetic CE ROM (ECEC signature, ROMHDR, one XIP module split into an
E32/O32 pair with a stored and a CECompress-coded section, plus a stored and a
compressed ROM file), runs `moria -e`, and asserts:

  * the image is identified as wince_rom at `verified` tier with the right
    module/file counts and span,
  * both ROM files come back byte-for-byte, the compressed one decoded,
  * the module is rebuilt into a PE whose sections land at their RVAs with the
    right bytes, including the section that was CECompress-coded,
  * a file that carries the ECEC signature but no resolvable ROMHDR (what a CE
    bootloader built from the same sources looks like) stays at `magic` tier and
    is not extracted.

Self-contained; no external tools. Exit nonzero on any failure.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
MORIA = os.path.join(HERE, "..", "build", "moria")

from lzxbuild import ce_compress_blob  # noqa: E402

BASE = 0x80200000          # virtual address the image is linked at
CPU_ARM = 0x01C2           # IMAGE_FILE_MACHINE_THUMB
SCN_COMPRESSED = 0x00002000
SCN_CODE = 0x00000020
SCN_WRITE = 0x80000000

TEXT = bytes(range(256)) * 12                       # 3072 B, stored verbatim
DATA = (b"CRESTRON-CE-SECTION-" * 300)[:5000]       # CECompress-coded section
PLAIN = b"[boot]\r\nDevice=CP3\r\n" * 40            # stored ROM file
PACKED = (b"ce-rom-file-payload;" * 900)[:17000]    # CECompress-coded ROM file

TEXT_RVA = 0x1000
DATA_RVA = 0x2000
# The .data section's virtual size exceeds its stored blob: CE zero-fills the
# tail at load time, and the extractor has to do the same rather than treat the
# short decode as a failure.
DATA_VSIZE = 0x2000
DATA_LOADED = DATA + bytes(DATA_VSIZE - len(DATA))
IMAGE_VSIZE = DATA_RVA + DATA_VSIZE


def build_rom():
    """Assemble a ROM image; returns the bytes."""
    img = bytearray(0x40)
    img += b"ECEC" + struct.pack("<II", 0, 0)   # pTOC / TOC offset, patched below

    def add(blob, align=4):
        while len(img) % align:
            img.append(0)
        off = len(img)
        img.extend(blob)
        return off                                 # file offset == VA - BASE

    def va(off):
        return BASE + off

    mod_name = add(b"test.dll\0", 1)
    f1_name = add(b"boot.ini\0", 1)
    f2_name = add(b"packed.bin\0", 1)

    text_off = add(TEXT)
    data_packed = ce_compress_blob(DATA, compress=True)   # Huffman-coded LZX
    data_off = add(data_packed)
    f1_off = add(PLAIN)
    packed = ce_compress_blob(PACKED)
    f2_off = add(packed)

    # O32ROMHDR: vsize, rva, psize, dataptr, realaddr, flags
    o32 = struct.pack("<6I", len(TEXT), TEXT_RVA, len(TEXT), va(text_off), BASE + TEXT_RVA,
                      SCN_CODE | 0x60000000)
    o32 += struct.pack("<6I", DATA_VSIZE, DATA_RVA, len(data_packed), va(data_off),
                       BASE + DATA_RVA, SCN_WRITE | 0x40000000 | SCN_COMPRESSED)
    o32_off = add(o32)

    # E32ROMHDR: the optional-header fields romimage keeps, then 6 data dirs.
    e32 = struct.pack("<HHII", 2, 0x210E, TEXT_RVA, BASE)      # objcnt, flags, entry, vbase
    e32 += struct.pack("<HH", 4, 0)                            # subsystem version
    e32 += struct.pack("<II", 0x10000, IMAGE_VSIZE)            # stackmax, vsize
    e32 += struct.pack("<II", 0, 0)                            # sect14 rva/size
    e32 += struct.pack("<I", 0x5A5A5A5A)                       # timestamp
    e32 += struct.pack("<12I", *([0] * 12))                    # 6 x (rva, size)
    e32_off = add(e32)

    toc = struct.pack("<8I", 0x20, 0, 0, len(TEXT) + DATA_VSIZE, va(mod_name), va(e32_off),
                      va(o32_off), BASE)
    filetab = struct.pack("<7I", 0x20, 0, 0, len(PLAIN), len(PLAIN), va(f1_name), va(f1_off))
    filetab += struct.pack("<7I", 0x20, 0, 0, len(PACKED), len(packed), va(f2_name), va(f2_off))

    while len(img) % 4:
        img.append(0)
    hdr_off = len(img)
    romhdr = struct.pack("<15I",
                         BASE,            # physfirst  (patched: physlast below)
                         0,               # physlast   (patched)
                         1,               # nummods
                         BASE + 0x400000, # ramstart
                         BASE + 0x410000, # ramfree
                         BASE + 0x800000, # ramend
                         0, 0,            # ncopy, copyoff
                         0, 0,            # proflen, profoff
                         2,               # numfiles
                         0,               # kernel flags
                         0x19191919,      # FS RAM percent
                         0, 0)            # drivglob start/len
    romhdr += struct.pack("<HH", CPU_ARM, 0)
    romhdr += struct.pack("<3I", 0, 0, 0)   # pExtensions, tracking start/len
    assert len(romhdr) == 0x4C
    img += romhdr + toc + filetab

    struct.pack_into("<I", img, 4, len(img))          # physlast, patched after the tables
    struct.pack_into("<I", img, 0x44, va(hdr_off))    # pTOC
    struct.pack_into("<I", img, 0x48, hdr_off)        # TOC offset from image start
    struct.pack_into("<I", img, hdr_off + 4, BASE + len(img))
    return bytes(img)


def build_stale_signature():
    """A bootloader-shaped file: real ECEC header, pTOC pointing nowhere."""
    img = bytearray(0x1000)
    img[0:4] = struct.pack("<I", 0xEA0003FE)          # ARM branch, as romimage emits
    img[0x40:0x4C] = b"ECEC" + struct.pack("<II", 0x82DA28F0, 0x02BA28F0)
    img[0x100:0x120] = b"Crestron Bootloader %d.%d\0\0\0\0\0\0\0"
    return bytes(img)


def run(path, outdir=None):
    cmd = [MORIA, "-j", path]
    if outdir:
        cmd = [MORIA, "-e", "-j", path, "-C", outdir]
    r = subprocess.run(cmd, capture_output=True, timeout=120)
    if r.returncode != 0:
        raise SystemExit("moria exited %d: %s" % (r.returncode, r.stderr.decode("replace")))
    return json.loads(r.stdout)


def fail(msg):
    print("FAIL:", msg)
    return 1


def pe_sections(pe):
    if pe[:2] != b"MZ":
        raise AssertionError("no MZ signature")
    nt = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[nt:nt + 4] != b"PE\0\0":
        raise AssertionError("no PE signature at e_lfanew")
    machine, nsec = struct.unpack_from("<HH", pe, nt + 4)
    opt_size = struct.unpack_from("<H", pe, nt + 20)[0]
    st = nt + 24 + opt_size
    out = []
    for i in range(nsec):
        name, vsize, rva, raw, ptr = struct.unpack_from("<8sIIII", pe, st + i * 40)
        out.append((name.rstrip(b"\0").decode(), vsize, rva, raw, ptr))
    return machine, out


def main():
    with tempfile.TemporaryDirectory() as tmp:
        rom = os.path.join(tmp, "nk.cos")
        with open(rom, "wb") as f:
            f.write(build_rom())

        j = run(rom)
        finds = [x for x in j["findings"] if x["type"] == "wince_rom"]
        if len(finds) != 1:
            return fail("expected exactly one wince_rom finding, got %d" % len(finds))
        f0 = finds[0]
        if f0["confidence_tier"] != "verified":
            return fail("tier is %s, want verified" % f0["confidence_tier"])
        if f0.get("label") != "1 modules, 2 files":
            return fail("label is %r" % f0.get("label"))
        if f0.get("compression") != "cecompress":
            return fail("compression is %r" % f0.get("compression"))
        if f0.get("arch") != "arm":
            return fail("arch is %r" % f0.get("arch"))
        if len(j["findings"]) != 1:
            return fail("ROM interior leaked extra findings: %r" %
                        [x["type"] for x in j["findings"]])

        outdir = os.path.join(tmp, "out")
        j = run(rom, outdir)
        ent = [e for e in j["extraction"]["extracted"] if e["type"] == "wince_rom"]
        if not ent or ent[0]["status"] != "ok":
            return fail("extraction status %r" % (ent[0]["status"] if ent else None))
        root = os.path.join(outdir, ent[0]["root"])

        got = open(os.path.join(root, "files", "boot.ini"), "rb").read()
        if got != PLAIN:
            return fail("stored ROM file differs (%d vs %d bytes)" % (len(got), len(PLAIN)))
        got = open(os.path.join(root, "files", "packed.bin"), "rb").read()
        if got != PACKED:
            return fail("CECompress ROM file differs (%d vs %d bytes)" % (len(got), len(PACKED)))

        pe = open(os.path.join(root, "modules", "test.dll"), "rb").read()
        machine, secs = pe_sections(pe)
        if machine != CPU_ARM:
            return fail("rebuilt PE machine is 0x%04x, want 0x%04x" % (machine, CPU_ARM))
        if len(secs) != 2:
            return fail("rebuilt PE has %d sections, want 2" % len(secs))
        by_rva = {s[2]: s for s in secs}
        if TEXT_RVA not in by_rva or DATA_RVA not in by_rva:
            return fail("sections at unexpected RVAs: %r" % (secs,))
        if by_rva[TEXT_RVA][0] != ".text":
            return fail("code section named %r" % by_rva[TEXT_RVA][0])
        if by_rva[DATA_RVA][0] != ".data":
            return fail("writable section named %r" % by_rva[DATA_RVA][0])
        for rva, want in ((TEXT_RVA, TEXT), (DATA_RVA, DATA_LOADED)):
            name, vsize, _, _, ptr = by_rva[rva]
            if ptr != rva:
                return fail("%s PointerToRawData 0x%x != RVA 0x%x" % (name, ptr, rva))
            if vsize != len(want):
                return fail("%s VirtualSize %d != %d" % (name, vsize, len(want)))
            if pe[rva:rva + len(want)] != want:
                return fail("%s bytes differ at its RVA" % name)

        # A stale ECEC signature must identify but never extract.
        stale = os.path.join(tmp, "eboot.cos")
        with open(stale, "wb") as f:
            f.write(build_stale_signature())
        outdir2 = os.path.join(tmp, "out2")
        j = run(stale, outdir2)
        finds = [x for x in j["findings"] if x["type"] == "wince_rom"]
        if len(finds) != 1 or finds[0]["confidence_tier"] != "magic":
            return fail("stale ECEC header: %r" % [(x["type"], x["confidence_tier"])
                                                   for x in j["findings"]])
        made = [e for e in j.get("extraction", {}).get("extracted", []) if e.get("files")]
        if made:
            return fail("stale ECEC header produced files: %r" % made)

    print("ok: wince_rom identify + module/file extraction")
    return 0


if __name__ == "__main__":
    sys.exit(main())

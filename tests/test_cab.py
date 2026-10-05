#!/usr/bin/env python3
"""Microsoft Cabinet identify + extract regression.

Builds four synthetic cabinets and checks each end to end:

  * stored folders, with per-structure reserve fields present (what Windows CE
    cabwiz emits) and a file whose data spans two CFDATA blocks,
  * MSZIP folders, where each block's DEFLATE stream uses the previous block's
    output as a preset dictionary,
  * an LZX folder spanning several 32 KiB output frames,
  * a Windows CE installer cabinet: mangled 8.3 members plus a _setup.xml, which
    must be rebuilt into the real install tree (fs/), a registry.reg, and the
    two cabwiz housekeeping members named for what they are.

Self-contained; no external tools. Exit nonzero on any failure.
"""
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
MORIA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "moria")

from lzxbuild import lzx_compress, lzx_stored_stream  # noqa: E402

COMP_NONE, COMP_MSZIP, COMP_LZX = 0, 1, 3
FRAME = 32768


def build_cab(folders, files, reserve=None):
    """Assemble a cabinet.

    folders: list of (typeCompress, [ (compressed_bytes, uncompressed_len), ... ])
    files:   list of (name, folder_index, offset_in_folder, size)
    reserve: optional (cbCFHeader, cbCFFolder, cbCFData)
    """
    res_hdr, res_fold, res_data = reserve or (0, 0, 0)
    flags = 0x0004 if reserve else 0

    hdr_len = 0x24 + (4 + res_hdr if reserve else 0)
    fold_stride = 8 + res_fold
    coff_files = hdr_len + len(folders) * fold_stride

    file_tab = b""
    for name, ifolder, off, size in files:
        file_tab += struct.pack("<IIHHHH", size, off, ifolder, 0x2A21, 0x5B20, 0x20)
        file_tab += name.encode() + b"\0"

    data_start = coff_files + len(file_tab)

    # Lay the CFDATA chains out folder by folder so each folder's start is known.
    blobs, folder_off, pos = b"", [], data_start
    for _, blocks in folders:
        folder_off.append(pos)
        for comp, ulen in blocks:
            blobs += struct.pack("<IHH", 0, len(comp), ulen) + bytes(res_data) + comp
            pos += 8 + res_data + len(comp)

    total = data_start + len(blobs)
    out = bytearray()
    out += struct.pack("<4sIIIIIBBHHHHH", b"MSCF", 0, total, 0, coff_files, 0, 3, 1,
                       len(folders), len(files), flags, 0x1234, 0)
    if reserve:
        out += struct.pack("<HBB", res_hdr, res_fold, res_data) + bytes(res_hdr)
    for (ctype, blocks), off in zip(folders, folder_off):
        out += struct.pack("<IHH", off, len(blocks), ctype) + bytes(res_fold)
    out += file_tab + blobs
    assert len(out) == total, (len(out), total)
    return bytes(out)


def stored_blocks(data, block=4096):
    return [(data[i:i + block], len(data[i:i + block])) for i in range(0, len(data), block)]


def mszip_blocks(data):
    """Split into 32 KiB frames, each DEFLATEd against the previous frame."""
    out, prev = [], b""
    for i in range(0, len(data), FRAME):
        chunk = data[i:i + FRAME]
        if prev:
            co = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=prev)
        else:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
        out.append((b"CK" + co.compress(chunk) + co.flush(zlib.Z_FINISH), len(chunk)))
        prev = (prev + chunk)[-FRAME:]
    return out


def lzx_blocks(data, nsplit=4):
    """One LZX bitstream for the folder, chopped across several CFDATA blocks.

    The uncompressed lengths must be the 32 KiB output frames; where the
    compressed bytes are cut between blocks is arbitrary, since a folder's
    blocks are concatenated back into one stream before decoding.
    """
    stream = lzx_stored_stream(data)
    frames = [len(data[i:i + FRAME]) for i in range(0, len(data), FRAME)]
    n = max(len(frames), nsplit)
    step = (len(stream) + n - 1) // n
    parts = [stream[i:i + step] for i in range(0, len(stream), step)]
    while len(parts) < len(frames):
        parts.append(b"")
    while len(parts) > len(frames):          # fold the tail into the last frame's block
        parts[-2] += parts[-1]
        parts.pop()
    return list(zip(parts, frames))


def lzx_real_payload(n=110000):
    """Bytes that exercise the whole compressed-LZX path.

    Mixes long back-references (matches, including ones reaching across a
    32 KiB frame boundary), incompressible runs (literals, so the main tree is
    genuinely Huffman-coded) and x86 CALL sites (so the E8 filter runs).
    """
    rnd = random.Random(1234)
    buf = bytearray()
    motif = bytes(rnd.randrange(256) for _ in range(900))
    while len(buf) < n:
        r = rnd.random()
        if r < 0.32:
            buf += motif[:rnd.randrange(40, 900)]
        elif r < 0.55:
            buf += b"\xe8" + struct.pack("<i", rnd.randrange(-40000, 40000))
        elif r < 0.75 and len(buf) > 40000:
            src = len(buf) - rnd.randrange(1, min(len(buf), 60000))
            buf += bytes(buf[src:src + rnd.randrange(8, 200)]) or b"\0"
        else:
            buf += bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 30)))
    return bytes(buf[:n])


def lzx_compressed_blocks(data, window_bits=21):
    """A real compressed LZX folder: one CFDATA block per 32 KiB output frame."""
    frames = lzx_compress(data, window_bits=window_bits, intel_filesize=len(data),
                          block_ends=[50000, 88000, len(data)], aligned_blocks=(1,))
    ulens = [len(data[i:i + FRAME]) for i in range(0, len(data), FRAME)]
    assert len(frames) == len(ulens), (len(frames), len(ulens))
    return list(zip(frames, ulens))


SETUP_XML = """<wap-provisioningdoc>
<characteristic type="Install">
<parm name="AppName" value="Moria Test Installer" />
<parm name="NumFiles" value="3" />
</characteristic>
<characteristic type="FileOperation">
<characteristic type="%CE2%" translation="install">
<characteristic type="MakeDir" />
<characteristic type="Agent.exe" translation="install">
<characteristic type="Extract">
<parm name="Source" value="AGENT~1.001" />
</characteristic>
</characteristic>
</characteristic>
<characteristic type="\\Sys\\SSH" translation="install">
<characteristic type="MakeDir" />
<characteristic type="host_key.pem" translation="install">
<characteristic type="Extract">
<parm name="Source" value="HOSTKE~1.002" />
</characteristic>
</characteristic>
</characteristic>
</characteristic>
<characteristic type="Registry">
<characteristic type="HKLM\\Crestron\\System">
<parm name="Version" value="1.8001.0298" datatype="string" />
<parm name="Build" value="298" datatype="integer" />
</characteristic>
</characteristic>
</wap-provisioningdoc>
""".encode()

AGENT = b"MZ" + b"\x90\x00" + bytes(200) + b"agent payload" * 50
HOSTKEY = b"-----BEGIN RSA PRIVATE KEY-----\n" + b"A" * 600 + b"\n-----END RSA PRIVATE KEY-----\n"
SETUP_DLL = b"MZ" + bytes(120) + b"setup dll body"
INSTALL_HDR = bytes(range(256)) * 4


def run(path, outdir=None):
    cmd = [MORIA, "-e", "-j", path, "-C", outdir] if outdir else [MORIA, "-j", path]
    r = subprocess.run(cmd, capture_output=True, timeout=180)
    if r.returncode != 0:
        raise SystemExit("moria exited %d: %s" % (r.returncode, r.stderr.decode("replace")))
    return json.loads(r.stdout)


def fail(msg):
    print("FAIL:", msg)
    return 1


def extract(tmp, name, blob):
    path = os.path.join(tmp, name)
    with open(path, "wb") as f:
        f.write(blob)
    outdir = os.path.join(tmp, name + ".out")
    j = run(path, outdir)
    ent = [e for e in j["extraction"]["extracted"] if e["type"] == "cab"]
    if not ent:
        raise AssertionError("no cab extraction for %s: %r" % (name, j["extraction"]))
    return j, ent[0], os.path.join(outdir, ent[0]["root"])


def check_roundtrip(tmp, name, folders, files, payloads, reserve=None, want_comp=None):
    blob = build_cab(folders, files, reserve)
    j, ent, root = extract(tmp, name, blob)
    finds = [x for x in j["findings"] if x["type"] == "cab"]
    if len(finds) != 1 or finds[0]["confidence_tier"] != "verified":
        return fail("%s: findings %r" % (name, [(x["type"], x["confidence_tier"])
                                                for x in j["findings"]]))
    if want_comp and finds[0].get("compression") != want_comp:
        return fail("%s: compression %r, want %r" % (name, finds[0].get("compression"), want_comp))
    if ent["status"] != "ok":
        return fail("%s: status %r (%r)" % (name, ent["status"], ent.get("warnings")))
    for member, want in payloads.items():
        p = os.path.join(root, member)
        if not os.path.isfile(p):
            return fail("%s: missing member %s" % (name, member))
        got = open(p, "rb").read()
        if got != want:
            return fail("%s: member %s differs (%d vs %d bytes)" %
                        (name, member, len(got), len(want)))
    return 0


def main():
    with tempfile.TemporaryDirectory() as tmp:
        # 1. Stored folders, CE-style reserve fields, a file spanning two blocks.
        a = b"stored-member-A;" * 400          # 6400 B: crosses the 4096 block boundary
        b = b"stored-member-B\n" * 100
        data = a + b
        rc = check_roundtrip(
            tmp, "stored.cab",
            folders=[(COMP_NONE, stored_blocks(data))],
            files=[("dir\\a.txt", 0, 0, len(a)), ("b.txt", 0, len(a), len(b))],
            payloads={"dir/a.txt": a, "b.txt": b},
            reserve=(8, 52, 4), want_comp="none")
        if rc:
            return rc

        # 2. MSZIP, several blocks, each matching back into the previous one.
        big = b"".join(struct.pack("<I", i) + b"mszip-payload-line\n" for i in range(6000))
        rc = check_roundtrip(
            tmp, "mszip.cab",
            folders=[(COMP_MSZIP, mszip_blocks(big))],
            files=[("big.bin", 0, 0, len(big))],
            payloads={"big.bin": big}, want_comp="mszip")
        if rc:
            return rc

        # 3. LZX across several output frames, window 21 (the CAB default).
        lz = bytes((i * 7 + (i >> 8)) & 0xFF for i in range(100000))
        rc = check_roundtrip(
            tmp, "lzx.cab",
            folders=[(COMP_LZX | (21 << 8), lzx_blocks(lz))],
            files=[("frames.bin", 0, 0, len(lz))],
            payloads={"frames.bin": lz}, want_comp="lzx")
        if rc:
            return rc

        # 4. A real *compressed* LZX folder: Huffman-coded verbatim and aligned
        #    blocks, matches, and the x86 filter, spanning four 32 KiB frames
        #    with block boundaries deliberately off the frame boundaries. This
        #    is the path every real-world LZX cabinet takes.
        real = lzx_real_payload()
        rc = check_roundtrip(
            tmp, "lzx-real.cab",
            folders=[(COMP_LZX | (21 << 8), lzx_compressed_blocks(real))],
            files=[("real.bin", 0, 0, len(real))],
            payloads={"real.bin": real}, want_comp="lzx")
        if rc:
            return rc

        # 5. A Windows CE installer cabinet, rebuilt from its _setup.xml.
        members = [("_setup.xml", SETUP_XML), ("AGENT~1.001", AGENT),
                   ("HOSTKE~1.002", HOSTKEY), ("SETUP.999", SETUP_DLL),
                   ("HEADER.000", INSTALL_HDR), ("EXTRA~1.500", b"unlisted member")]
        stream = b"".join(p for _, p in members)
        files, off = [], 0
        for nm, p in members:
            files.append((nm, 0, off, len(p)))
            off += len(p)
        blob = build_cab([(COMP_NONE, stored_blocks(stream))], files, reserve=(0, 52, 0))
        j, ent, root = extract(tmp, "ceinstall.cab", blob)
        if ent["status"] != "ok":
            return fail("CE cab status %r (%r)" % (ent["status"], ent.get("warnings")))

        want = {
            "_setup.xml": SETUP_XML,
            "fs/Windows/Agent.exe": AGENT,
            "fs/Sys/SSH/host_key.pem": HOSTKEY,
            "setup.dll": SETUP_DLL,
            "install-header.000": INSTALL_HDR,
            "unmapped/EXTRA~1.500": b"unlisted member",
        }
        for rel, blobw in want.items():
            p = os.path.join(root, rel)
            if not os.path.isfile(p):
                return fail("CE cab: missing %s (have %r)" %
                            (rel, sorted(os.listdir(root))))
            if open(p, "rb").read() != blobw:
                return fail("CE cab: %s differs" % rel)

        reg = open(os.path.join(root, "registry.reg"), "r").read()
        for line in ("[HKEY_LOCAL_MACHINE\\Crestron\\System]",
                     '"Version"="1.8001.0298"',
                     '"Build"=dword:0000012a'):
            if line not in reg:
                return fail("CE cab: registry.reg missing %r:\n%s" % (line, reg))

    print("ok: cab identify + stored/MSZIP/LZX (stored and compressed) extraction"
          " + CE install-tree rebuild")
    return 0


if __name__ == "__main__":
    sys.exit(main())

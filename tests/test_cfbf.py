#!/usr/bin/env python3
"""Compound file (CFBF/MSI) identify + extract regression.

A compound file stores each stream as a chain of sectors interleaved with every
other stream, so a stream's bytes are not contiguous. That is the whole reason
this handler exists: an installer keeps its payload cabinet in a stream, and
reading it linearly from the MSCF magic yields one correct sector run followed
by another stream's bytes. The fixture here is built deliberately fragmented,
and asserts up front that a linear read does NOT reproduce the stream -- so the
test cannot quietly pass against a reader that ignores the FAT.

Checks:
  * the compound file is identified as cfbf at `verified` tier, flagged msi,
  * MSI-encoded stream names are decoded ("Data1.cab", not CJK mojibake),
  * a large fragmented stream comes back byte-for-byte,
  * a small stream (under the 4096-byte cutoff, so it lives in the mini stream
    addressed by the mini-FAT) comes back byte-for-byte,
  * recursion reads the cabinets inside -- both a compressed (LZX) and a stored
    one.
  * a compound file nested inside other extracted output is identified but left
    packed by default, and unpacked on --unpack-executables.

Self-contained; no external tools. Exit nonzero on any failure.
"""
import json
import os
import random
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
MORIA = os.path.join(HERE, "..", "build", "moria")

import cfbfbuild  # noqa: E402
from test_cab import (build_cab, lzx_compressed_blocks, lzx_real_payload,  # noqa: E402
                      stored_blocks)

COMP_NONE, COMP_LZX = 0, 3


def run(path, outdir=None, extra=()):
    cmd = [MORIA, "-e", "-j", path, "-C", outdir, *extra] if outdir else [MORIA, "-j", path]
    r = subprocess.run(cmd, capture_output=True, timeout=300)
    if r.returncode != 0:
        raise SystemExit("moria exited %d: %s" % (r.returncode, r.stderr.decode("replace")))
    return json.loads(r.stdout)


def fail(msg):
    print("FAIL:", msg)
    return 1


def find_file(root, name):
    for dirpath, _, files in os.walk(root):
        if name in files:
            return os.path.join(dirpath, name)
    return None


def main():
    rnd = random.Random(99)
    member = lzx_real_payload(90000)
    cab = build_cab([(COMP_LZX | (21 << 8), lzx_compressed_blocks(member))],
                    [("payload.bin", 0, 0, len(member))])
    # A stored cabinet too: its member sits verbatim in the stream, so sectors
    # reassembled in the wrong order surface as wrong bytes instead of a codec
    # error. Non-repeating content, so a swapped sector cannot go unnoticed.
    stored_member = bytes(rnd.randrange(256) for _ in range(30000))
    stored_cab = build_cab([(COMP_NONE, stored_blocks(stored_member))],
                           [("stored.bin", 0, 0, len(stored_member))])
    big = bytes(rnd.randrange(256) for _ in range(40000))
    small = b"summary stream, under the mini-stream cutoff\n" * 20

    blob = cfbfbuild.build([
        (cfbfbuild.msi_mangle("Data1.cab"), cab),         # compressed, MSI-encoded name
        (cfbfbuild.msi_mangle("Data2.cab"), stored_cab),  # stored
        ("BigStream", big),
        ("_SummaryInformation", small),
    ])

    # The fixture must actually be fragmented, else it proves nothing: neither
    # cabinet may appear contiguously anywhere in the file, or a reader that
    # ignores the FAT would pass this test.
    if blob.find(b"MSCF") < 0:
        return fail("fixture has no MSCF in it at all")
    for label, c in (("Data1.cab", cab), ("Data2.cab", stored_cab)):
        if c in blob:
            return fail("fixture is contiguous for %s: a linear read would succeed, "
                        "so the test could not detect a reader that ignores the FAT"
                        % label)

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "installer.msi")
        with open(path, "wb") as f:
            f.write(blob)
        out = os.path.join(tmp, "out")
        j = run(path, out)

        finds = [x for x in j["findings"] if x["type"] == "cfbf"]
        if len(finds) != 1:
            return fail("expected one cfbf finding, got %d" % len(finds))
        f0 = finds[0]
        if f0["confidence_tier"] != "verified":
            return fail("tier is %s, want verified" % f0["confidence_tier"])
        if f0["offset"] != 0:
            return fail("cfbf found at offset %d, want 0" % f0["offset"])
        if "msi" not in (f0.get("label") or ""):
            return fail("label %r does not flag msi" % f0.get("label"))
        if f0.get("size") != len(blob):
            return fail("size %r != file size %d" % (f0.get("size"), len(blob)))
        print("  PASS  identified as cfbf, verified, msi, exact span")

        # A cab finding inside the compound file must not survive as a peer: it
        # is the stream's first sector run, and extracting it linearly is what
        # produced garbage before this handler existed.
        stray = [x for x in j["findings"] if x["type"] == "cab" and x["offset"] != 0]
        if stray:
            return fail("interior cab finding at 0x%x not suppressed by the container"
                        % stray[0]["offset"])
        print("  PASS  interior cab match suppressed by the enclosing compound file")

        for label, want in (("Data1.cab", cab), ("Data2.cab", stored_cab)):
            got = find_file(out, label)
            if not got:
                return fail("MSI-encoded stream name was not decoded to " + label)
            if open(got, "rb").read() != want:
                return fail("%s stream did not round-trip byte-for-byte" % label)
        print("  PASS  MSI names decoded; both cab streams byte-exact "
              "(compressed + stored)")

        gb = find_file(out, "BigStream")
        if not gb or open(gb, "rb").read() != big:
            return fail("BigStream did not round-trip byte-for-byte")
        print("  PASS  large fragmented stream byte-exact")

        gs = find_file(out, "_SummaryInformation")
        if not gs or open(gs, "rb").read() != small:
            return fail("mini-stream (under the 4096 cutoff) did not round-trip")
        print("  PASS  mini-FAT stream byte-exact")

        for label, name, want in (("compressed", "payload.bin", member),
                                  ("stored", "stored.bin", stored_member)):
            gm = find_file(out, name)
            if not gm:
                return fail("recursion did not extract the %s cabinet inside the stream"
                            % label)
            if open(gm, "rb").read() != want:
                return fail("%s cab member inside the MSI did not round-trip "
                            "byte-for-byte" % label)
        print("  PASS  both cabinets extracted from their streams, members byte-exact")

    rc = nesting_policy()
    if rc:
        return rc
    rc = executable_carrier_policy()
    if rc:
        return rc
    rc = deep_directory_chain()
    if rc:
        return rc

    print("ok: cfbf identify + MSI name decode + fragmented stream reassembly"
          " + nesting policy + deep-directory walk")
    return 0


def deep_directory_chain():
    """A crafted directory must not overflow the stack during extraction.

    The directory is a red-black tree of siblings plus storage children; nothing
    forces it to be balanced, so a hostile compound file can lay its entries out
    as one long linear chain. A recursive walk overflowed the call stack on this
    (a ~120k-entry chain segfaults `moria -e`); the walk is now iterative, so any
    depth up to the 262144-entry cap is safe. The deepest entry carries a payload
    that must come back byte-for-byte, proving the walk reached the end rather
    than bailing out early.

    The chain length is sized to blow a default 8 MiB stack on the old recursive
    code; `run()` raises on the resulting segfault, so this fails loudly if the
    recursion ever comes back.
    """
    payload = b"deepest-entry-must-survive-" * 400
    blob = cfbfbuild.build_deep_chain(120000, payload=payload)

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "deep.msi")
        with open(path, "wb") as f:
            f.write(blob)
        out = os.path.join(tmp, "out")
        j = run(path, out)  # a stack-overflow segfault would raise here

        finds = [x for x in j["findings"] if x["type"] == "cfbf"]
        if len(finds) != 1:
            return fail("deep-chain file not identified as a single cfbf (got %d)" % len(finds))

        got = find_file(out, "deep")
        if got is None:
            return fail("the deepest entry in the chain was not walked/extracted")
        if open(got, "rb").read() != payload:
            return fail("deepest entry did not round-trip byte-for-byte")
        print("  PASS  120k-deep directory chain extracted without stack overflow")
    return 0


def nesting_policy():
    """A compound file below the top level stays packed unless asked for.

    An MSI unpacks to hundreds of database-table streams. When one is incidental
    cargo inside something else -- an installer cabinet shipping a redistributable
    -- those streams bury the findings that matter, so they are identified and
    counted but not written. The file the user actually pointed at is different:
    there the container IS the subject, so it is always unpacked.
    """
    inner = cfbfbuild.build([("Payload", b"nested msi payload\n" * 400),
                             ("_SummaryInformation", b"summary" * 40)])
    # Wrap it in a stored cabinet, so the compound file only appears one level
    # down, in what the cabinet extractor produced.
    wrapper = build_cab([(0, stored_blocks(inner))],
                        [("installer.msi", 0, 0, len(inner))])

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "outer.cab")
        with open(path, "wb") as f:
            f.write(wrapper)

        out = os.path.join(tmp, "default")
        j = run(path, out)
        if find_file(out, "installer.msi") is None:
            return fail("the cabinet member itself should still be extracted")
        if find_file(out, "Payload") is not None:
            return fail("nested compound file was unpacked without --unpack-executables")
        if j["extraction"].get("skipped_nested_executables") != 1:
            return fail("skipped_nested_executables is %r, want 1"
                        % j["extraction"].get("skipped_nested_executables"))
        print("  PASS  nested compound file left packed, and the skip is reported")

        out2 = os.path.join(tmp, "optin")
        j2 = run(path, out2, extra=("--unpack-executables",))
        got = find_file(out2, "Payload")
        if got is None:
            return fail("--unpack-executables did not unpack the nested compound file")
        if open(got, "rb").read() != b"nested msi payload\n" * 400:
            return fail("nested stream did not round-trip under --unpack-executables")
        if j2["extraction"].get("skipped_nested_executables"):
            return fail("skipped_nested_executables should be absent once the opt-in "
                        "is given")
        print("  PASS  --unpack-executables unpacks it, byte-exact")
    return 0


def executable_carrier_policy():
    """Extraction does not dig inside an executable it produced itself.

    Vendor installers ship a redistributable, which ships its own setup.exe,
    which carries another cabinet. Following that turns one firmware image into a
    tree of everything the vendor ever bundled, so a produced PE/ELF is left
    alone -- the gate is on the carrier, not on what is inside it. The file named
    on the command line is exempt: it never reaches this path.
    """
    buried = b"payload inside a nested executable\n" * 300
    inner_cab = build_cab([(COMP_NONE, stored_blocks(buried))],
                          [("buried.bin", 0, 0, len(buried))])
    # A PE-shaped carrier: an MZ header, then the cabinet at an offset.
    exe = b"MZ" + b"\x90\x00" + bytes(508) + inner_cab
    wrapper = build_cab([(COMP_NONE, stored_blocks(exe))],
                        [("nested.exe", 0, 0, len(exe))])

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "outer.cab")
        with open(path, "wb") as f:
            f.write(wrapper)

        out = os.path.join(tmp, "default")
        j = run(path, out)
        got = find_file(out, "nested.exe")
        if got is None or open(got, "rb").read() != exe:
            return fail("the executable member itself should still be extracted")
        if find_file(out, "buried.bin") is not None:
            return fail("dug into a nested executable without --unpack-executables")
        if j["extraction"].get("skipped_nested_executables") != 1:
            return fail("skipped_nested_executables is %r, want 1"
                        % j["extraction"].get("skipped_nested_executables"))
        print("  PASS  nested executable not dug into, and the skip is reported")

        out2 = os.path.join(tmp, "optin")
        run(path, out2, extra=("--unpack-executables",))
        gb = find_file(out2, "buried.bin")
        if gb is None or open(gb, "rb").read() != buried:
            return fail("--unpack-executables did not reach the cabinet inside the exe")
        print("  PASS  --unpack-executables reaches it, byte-exact")
    return 0


if __name__ == "__main__":
    sys.exit(main())

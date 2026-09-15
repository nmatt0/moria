#!/usr/bin/env python3
"""Human-output extraction tree regression (issue #25).

`moria -e` in human mode must render the recursively-extracted tree, not just the
top-level finding: each extracted child nested under its parent, the locator column
showing the child's byte offset within the file it came from plus that file's name
when it is a real member (and NOT for moria's synthetic single-payload outputs like
`decompressed`).

Self-contained: builds a nested zip -> gzip -> gzip fixture with the stdlib only
(no mksquashfs/mkfs tools), so it always runs as a hard gate. Run:
    python3 tests/test_human_tree.py
"""
import gzip
import io
import os
import random
import re
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

# ANSI stripper so assertions run on plain text (moria colorizes only on a tty,
# but strip defensively in case that changes).
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def build_fixture(path):
    """A zip (stored) whose member is a gzip stream that decompresses to a blob
    holding two more gzip streams: one at offset 0, one at a nonzero offset.
    Extraction is therefore:
        zip -> payload-A.gz (gzip, a real member @ file offset 0)
                 -> [decompressed blob]
                      -> gzip @0x0        (nameless synthetic payload, offset 0)
                      -> gzip @<nonzero>  (nameless synthetic payload, embedded)
    This exercises every locator case: a named member at offset 0 (name shown, no
    0x0), a nameless child at offset 0 (0x0 kept so the line is not bare), and a
    nameless child at a real nonzero offset. Payloads are incompressible (fixed-seed
    PRNG) so every produced gzip clears moria's 64-byte descend floor.
    """
    rnd = random.Random(0xC0FFEE)
    a = gzip.compress(bytes(rnd.getrandbits(8) for _ in range(8000)))  # sits at blob 0x0
    b = gzip.compress(bytes(rnd.getrandbits(8) for _ in range(8000)))  # sits at a nonzero off
    blob = a + b"\x00" * 256 + b
    member = gzip.compress(blob)  # the member: decompresses to `blob`
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr("payload-A.gz", member)
    with open(path, "wb") as f:
        f.write(buf.getvalue())


def main():
    if not os.path.exists(MORIA):
        print("moria binary not built; run cmake --build build first", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as td:
        fw = os.path.join(td, "nested.bin")
        build_fixture(fw)
        out = subprocess.run(
            [MORIA, "-e", "-C", os.path.join(td, "ex"), fw],
            capture_output=True, text=True, check=True,
        ).stdout
    text = ANSI.sub("", out)
    lines = text.splitlines()
    print(text)

    failures = []

    def want(cond, msg):
        if not cond:
            failures.append(msg)

    # A findings/extraction table header.
    want(any(l.startswith("OFFSET") and "TYPE" in l for l in lines), "no table header")

    # The top-level zip row (a root, no tree glyphs).
    want(any(l.startswith("0x0 ") and re.search(r"\bzip\b", l) for l in lines),
         "no top-level zip row")

    # Tree connectors: the extraction descendants must be drawn nested, not flat.
    want(any(("└─" in l or "├─" in l) for l in lines), "no tree connectors (not nested)")

    # The real member name is shown in the locator (it disambiguates which member),
    # and a member at file offset 0 shows the name WITHOUT a redundant 0x0.
    mem = [l for l in lines if "payload-A.gz" in l and "gzip" in l]
    want(bool(mem), "member name not shown")
    want(mem and not re.search(r"\b0x0\b", mem[0]), "named offset-0 member printed a redundant 0x0")

    # A nameless (synthetic-payload) child at offset 0 must still print 0x0 so the
    # line is never bare; it is a child row (has a connector) and is not the top row.
    child_rows = [l for l in lines if ("└─" in l or "├─" in l)]
    want(any(re.search(r"\b0x0\b", l) for l in child_rows),
         "nameless offset-0 child dropped its 0x0 (bare line)")

    # A nameless child at a real nonzero offset must surface that offset.
    want(any(re.search(r"0x[0-9a-f]+\b", l) and "gzip" in l and "payload-A.gz" not in l
             for l in child_rows), "embedded nonzero-offset child not shown with its offset")

    # Every child row has a non-empty locator (a name or an offset), never blank.
    def locator_blank(l):
        after = l.split("─", 1)[-1] if "─" in l else l
        return not re.search(r"(0x[0-9a-f]+|payload-A\.gz)", after)
    want(not any(locator_blank(l) for l in child_rows), "a child row had a blank locator")

    # moria's synthetic single-payload name must NOT appear as a breadcrumb.
    want(not any("decompressed" in l for l in lines), "synthetic 'decompressed' leaked into the tree")

    # Descendant rows carry the same TIER + NOTES a standalone scan would: the child
    # gzip rows must show a confidence tier and their endian note, not blanks.
    tiers = ("magic", "structural", "consistent", "verified")
    want(any(any(t in l for t in tiers) and "little" in l for l in child_rows),
         "extracted child rows are missing TIER/NOTES enrichment")

    # The nested count must exceed the single top-level finding (proves parity fix).
    want(len(child_rows) >= 2, "expected >=2 nested child rows")

    if failures:
        print("-" * 60)
        for m in failures:
            print("FAIL:", m)
        return 1
    print("-" * 60)
    print("PASS: human -e renders the nested extraction tree (offsets, member names, "
          "synthetic-name suppression)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

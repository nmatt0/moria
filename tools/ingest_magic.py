#!/usr/bin/env python3
"""Ingest file(1)'s Magdir into a generated Wave-2 signature set.

We translate only the tractable subset of the magic(5) DSL: top-level (level-0)
rules with a fixed non-negative offset and a *literal* string or numeric magic.
Anything needing the DSL's runtime (indirect/relative offsets, masks, search,
regex, name/use, relational tests, "any" matches) is skipped. Each surviving
rule becomes an offset-anchored (short=true) magic-tier signature, so the
generated set behaves like `file` (identify a whole file by bytes at a fixed
offset) and never carves the whole buffer.

Output: a TOML file, one [[signature]] per rule.

Usage:
  tools/ingest_magic.py [--out FILE] [--min-len N] [--strings-only] [MAGDIR ...]
Defaults ingest file(1)'s Magdir into signatures-generated/generated.toml.
Firmware set (strings-only, distinctive) is produced by a second invocation over
the fkie firmware-magic-database; see tools/gen_signatures.sh.
"""
import argparse
import glob
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MAGDIR = os.path.join(HERE, "..", "..", "repos", "file", "magic", "Magdir")
OUT = os.path.join(HERE, "..", "signatures-generated", "generated.toml")

NUMERIC = {
    "byte": (1, "le"), "ubyte": (1, "le"),
    "short": (2, "le"), "ushort": (2, "le"),
    "leshort": (2, "le"), "uleshort": (2, "le"),
    "beshort": (2, "be"), "ubeshort": (2, "be"),
    "long": (4, "le"), "ulong": (4, "le"),
    "lelong": (4, "le"), "ulelong": (4, "le"),
    "belong": (4, "be"), "ubelong": (4, "be"),
    "quad": (8, "le"), "lequad": (8, "le"), "bequad": (8, "be"),
}

MIN_MAGIC_LEN = 2  # bytes; shorter magics are too noisy even when offset-anchored

# Polyglot magics whose Magdir name is a conditional sub-variant. Borrowing the
# first continuation label mislabels the whole family (a .docx as a KMZ), so pin
# a clean generic label by magic prefix.
PREFIX_LABEL = [
    (b"PK\x03\x04", "ZIP archive (or ZIP-based: docx/xlsx/epub/jar/apk/kmz)"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"PK\x07\x08", "ZIP archive (spanned)"),
    (b"<?xml", "XML document"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
]


def tokenize(line):
    """Split a magic line into (offset, type, test, message), honoring backslash
    escapes inside the test field. Returns None if it can't be parsed."""
    i, n = 0, len(line)

    def read_field():
        nonlocal i
        while i < n and line[i] in " \t":
            i += 1
        start = i
        while i < n and line[i] not in " \t":
            i += 1
        return line[start:i]

    offset = read_field()
    typ = read_field()
    # test field: respect backslash escapes (so "\ " stays part of the token)
    while i < n and line[i] in " \t":
        i += 1
    start = i
    while i < n:
        c = line[i]
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c in " \t":
            break
        i += 1
    test = line[start:i]
    message = line[i:].strip()
    if not offset or not typ or not test:
        return None
    return offset, typ, test, message


def unescape(s):
    """Decode a magic(5) string test into bytes. Returns None on anything odd."""
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c != "\\":
            out.append(ord(c) & 0xFF)
            i += 1
            continue
        i += 1
        if i >= n:
            return None
        e = s[i]
        if e == "x":
            j = i + 1
            hexs = ""
            while j < n and len(hexs) < 2 and s[j] in "0123456789abcdefABCDEF":
                hexs += s[j]
                j += 1
            if not hexs:
                return None
            out.append(int(hexs, 16))
            i = j
        elif e in "01234567":
            j = i
            octs = ""
            while j < n and len(octs) < 3 and s[j] in "01234567":
                octs += s[j]
                j += 1
            out.append(int(octs, 8) & 0xFF)
            i = j
        else:
            simple = {"n": 10, "r": 13, "t": 9, "b": 8, "f": 12, "v": 11, "a": 7,
                      "\\": 92, " ": 32}
            out.append(simple.get(e, ord(e) & 0xFF))
            i += 1
    return bytes(out)


def parse_offset(tok):
    try:
        return int(tok, 16) if tok.lower().startswith("0x") else int(tok)
    except ValueError:
        return None


def numeric_bytes(typ, test):
    width, endian = NUMERIC[typ]
    t = test
    if t and t[0] in "=<>&^~!":
        if t[0] != "=":
            return None  # relational test, not an exact match
        t = t[1:]
    try:
        val = int(t, 16) if t.lower().startswith("0x") else int(t, 0) if t.startswith("0") and len(t) > 1 else int(t)
    except ValueError:
        return None
    # Small values (length prefixes, small counts) match padding everywhere.
    if -0x10000 < val < 0x10000:
        return None
    try:
        return val.to_bytes(width, "big" if endian == "be" else "little", signed=val < 0)
    except (OverflowError, ValueError):
        return None


def string_bytes(typ, test):
    if test in ("x", ""):
        return None
    t = test
    if t and t[0] in "=<>&^~!":
        if t[0] != "=":
            return None
        t = t[1:]
    return unescape(t)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--min-len", type=int, default=MIN_MAGIC_LEN)
    ap.add_argument("--strings-only", action="store_true")
    ap.add_argument("dirs", nargs="*", default=[DEFAULT_MAGDIR])
    args = ap.parse_args()
    magdirs = args.dirs or [DEFAULT_MAGDIR]
    out_path = args.out
    min_len = args.min_len
    strings_only = args.strings_only
    files = []
    for d in magdirs:
        if os.path.isdir(d):
            files += sorted(glob.glob(os.path.join(d, "*")))
        elif os.path.isfile(d):
            files.append(d)

    seen = set()
    entries = []
    skipped = 0
    for path in files:
        if not os.path.isfile(path):
            continue
        try:
            lines = open(path, encoding="latin-1").read().splitlines()
        except OSError:
            continue
        for li, line in enumerate(lines):
            if not line or line[0] in "#>&" or line[0] in " \t":
                continue  # comment, continuation, or indented (level > 0)
            tok = tokenize(line)
            if not tok:
                continue
            offset, typ, test, message = tok
            # Many formats carry the human-readable name on a continuation line,
            # not the level-0 magic line. If this line has no message, borrow the
            # first non-empty message from the continuation lines that follow.
            if not message:
                for nxt in lines[li + 1:]:
                    if not nxt or nxt[0] == "#":
                        continue
                    if nxt[0] not in ">&" and nxt[0] not in " \t":
                        break  # reached the next level-0 rule
                    ctok = tokenize(nxt.lstrip(">& \t"))
                    if ctok and ctok[3]:
                        message = ctok[3]
                        break
            off = parse_offset(offset)
            if off is None or off < 0 or off > 4096:
                skipped += 1
                continue
            base_type = typ.split("/", 1)[0]  # allow string/flags
            if "&" in typ:
                skipped += 1
                continue
            if base_type == "string":
                magic = string_bytes(base_type, test)
            elif base_type in NUMERIC and not strings_only:
                # Numeric magics under 4 bytes match far too many unrelated files
                # (and would mislabel them); require >= 4 bytes.
                if NUMERIC[base_type][0] < 4:
                    skipped += 1
                    continue
                magic = numeric_bytes(base_type, test)
            else:
                skipped += 1
                continue
            if not magic or len(magic) < min_len:
                skipped += 1
                continue
            # Drop trivially-common magics (all-zero / all-0xFF) and all-control
            # strings; they match padding and produce confident-looking noise.
            uniq = set(magic)
            if uniq <= {0} or uniq <= {0xFF} or all(b < 0x20 for b in magic):
                skipped += 1
                continue
            desc = message.replace("\\b", "").strip()
            for prefix, label in PREFIX_LABEL:
                if off == 0 and magic.startswith(prefix):
                    desc = label
                    break
            if not desc:
                skipped += 1  # unnameable rule: don't emit a "..._magic" label
                continue
            key = (off, magic)
            if key in seen:
                continue
            seen.add(key)
            entries.append((off, magic, desc, base_type))

    def slug(desc, base_type):
        s = "".join(c.lower() if c.isalnum() else "_" for c in desc)
        while "__" in s:
            s = s.replace("__", "_")
        s = s.strip("_")[:40].strip("_")
        if not s or s[0].isdigit():
            s = "fmt_" + s
        return s or base_type

    # Provenance header, source-aware: the firmware set is derived from the fkie
    # firmware-magic-database (GPL-3.0); the general set from file(1)'s Magdir
    # (BSD-style). Only the magic *bytes* are used (facts); descriptions are
    # copied labels. Regenerated files carry the correct source + license note.
    from_fkie = any("firmware-magic-database" in d for d in magdirs)
    if from_fkie:
        src_line = ("# GENERATED by tools/ingest_magic.py from the fkie "
                    "firmware-magic-database (GPL-3.0). See THIRD_PARTY.md.")
    else:
        src_line = ("# GENERATED by tools/ingest_magic.py from file(1)'s Magdir "
                    "(BSD-style). See THIRD_PARTY.md.")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        f.write(src_line + "\n")
        f.write("# Offset-anchored, magic-tier signatures. Do not edit by hand; re-run the ingester.\n\n")
        for off, magic, desc, base_type in entries:
            hexs = magic.hex()
            d = desc.replace("\\", "\\\\").replace('"', '\\"')
            d = "".join(ch for ch in d if ch >= " ")[:200]
            f.write("[[signature]]\n")
            f.write(f'name = "{slug(desc, base_type)}"\n')
            f.write('category = "generic"\n')
            f.write(f"magic_offset = {off}\n")
            f.write("short = true\n")
            f.write(f'magic = [ {{ hex = "{hexs}", endian = "little" }} ]\n')
            f.write(f'doc = {{ description = "{d}" }}\n\n')

    print(f"wrote {len(entries)} signatures to {out_path} (skipped {skipped} untranslatable rules)")


if __name__ == "__main__":
    main()

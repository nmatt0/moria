#!/usr/bin/env python3
"""Compare moria's file-type results with file, binwalk, and unblob.

The script runs each installed program on every test file, gives equivalent
type names one shared label, and reports where the programs disagree. This is
a review aid, not a required check. It shows both moria's missed or incorrect
labels and cases where moria gives the better answer.

Test files are grouped in folders named for their expected type, such as
fs-squashfs, uimage, or dtb. Full-flash files can contain several types, so they
are checked only for agreement. Reports can include test filenames, so they are
written to the Git-ignored diff-report/ folder by default.

Usage:
  tests/diff_harness.py [--corpus DIR] [--out DIR] [--per-cat N]
                        [--max-bytes N] [--timeout S] [--workers N]
                        [--categories a,b,c] [--no-binwalk] [--no-file]

Set --corpus to a local firmware collection whose folders name the expected type.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")
SIGS = os.path.join(HERE, "..", "signatures")

# ---------------------------------------------------------------------------
# Equivalent file-type names used by the different programs. For example,
# squashfs and squashfs_legacy should count as the same answer.
# ---------------------------------------------------------------------------
FAMILY = {
    "squashfs": "squashfs", "squashfs_legacy": "squashfs",
    "ubi": "ubi", "ubifs": "ubi",
    "fat": "fat", "fat12": "fat", "fat16": "fat", "fat32": "fat", "vfat": "fat",
    "ext": "ext", "ext2": "ext", "ext3": "ext", "ext4": "ext",
    "dtb": "dtb", "fit": "dtb", "fdt": "dtb", "devicetree": "dtb",
    "device_tree": "dtb", "flattened_device_tree": "dtb",
    "elf": "elf",
    "ihex": "ihex", "intel_hex": "ihex",
    "android_boot": "android_boot", "androidboot": "android_boot",
    "android_bootimg": "android_boot", "bootimg": "android_boot",
    "android_sparse": "android_sparse", "sparse": "android_sparse",
    "jffs2": "jffs2",
    "yaffs2": "yaffs2", "yaffs": "yaffs2",
    "romfs": "romfs",
    "cramfs": "cramfs",
    "f2fs": "f2fs",
    "erofs": "erofs",
    "exfat": "exfat", "ntfs": "ntfs", "iso9660": "iso9660",
    "hfsplus": "hfsplus", "hfsx": "hfsplus",
    "xfs": "xfs", "btrfs": "btrfs",
    "uimage": "uimage",
    "rpi_eeprom": "rpi_eeprom",
    "uboot": "uboot", "lk": "lk",
    "zip": "zip", "tar": "tar", "cpio": "cpio",
    "gzip": "gzip", "xz": "xz", "zstd": "zstd", "lz4": "lz4", "bzip2": "bzip2",
    "7z": "7z", "rar": "rar", "lzma": "lzma", "lzop": "lzop",
    "png": "png", "jpeg": "jpeg", "gif": "gif", "bmp": "bmp", "pdf": "pdf",
    "certificate": "certificate", "private_key": "private_key",
    # general formats (for the --broad / format-corpus comparison)
    "xml": "xml", "html": "html", "text": "text", "tiff": "tiff", "webp": "webp",
    "svg": "svg", "epub": "epub", "mobipocket": "mobipocket", "isomedia": "isomedia",
    "matroska": "matroska", "avi": "avi", "mpeg": "mpeg", "flac": "flac",
    "mp3": "mp3", "wav": "wav", "ogg": "ogg", "docx": "docx", "xlsx": "xlsx",
    "pptx": "pptx", "msoffice": "msoffice", "rtf": "rtf",
}

# Substring rules for the long Magdir-derived tokens moria emits under --broad
# (e.g. "tiff_image_data_little_endian", "iso_media", "mobipocket_e_book") and
# any token not matched exactly above. Ordered; first hit wins. Applied to the
# already-lowercased token AFTER the exact FAMILY lookup misses.
SUBSTR_CANON = [
    ("tiff", "tiff"), ("iso_media", "isomedia"), ("isomedia", "isomedia"),
    ("quicktime", "isomedia"), ("mp4", "isomedia"), ("mobipocket", "mobipocket"),
    ("epub", "epub"), ("xml", "xml"), ("html", "html"), ("svg", "svg"),
    ("webp", "webp"), ("matroska", "matroska"), ("webm", "matroska"),
    ("flac", "flac"), ("ogg", "ogg"), ("microsoft_word", "docx"),
    ("microsoft_excel", "xlsx"), ("powerpoint", "pptx"),
    ("composite_document", "msoffice"), ("compound_document", "msoffice"),
    ("rich_text", "rtf"), ("jpeg_2000", "jp2k"),
    ("git_pack_index", "git"), ("git_pack", "git"), ("git_index", "git"),
    ("desktop_services", "dsstore"), ("wordperfect", "wordperfect"),
    ("microsoft_access", "access"), ("indesign", "indesign"),
    ("aportisdoc", "palmdoc"), ("palmdoc", "palmdoc"),
    ("microsoft_reader_ebook", "ebook"), ("bbeb", "ebook"),
    ("_text", "text"), ("ascii_text", "text"),
]


def canon(tok):
    if not tok:
        return "unknown"
    t = tok.strip().lower()
    if t in FAMILY:
        return FAMILY[t]
    for needle, fam in SUBSTR_CANON:
        if needle in t:
            return fam
    return t


# category dir -> canonical ground-truth type. None => container / no single top
# type (agreement scored, correctness not).
GROUND_TRUTH = {
    "fs-squashfs": "squashfs", "fs-jffs2": "jffs2", "fs-ubi": "ubi",
    "fs-erofs": "erofs", "fs-ext": "ext", "fs-romfs": "romfs",
    "fs-yaffs": "yaffs2", "uimage": "uimage", "android-boot": "android_boot",
    "android-sparse": "android_sparse", "dtb": "dtb", "mcu-elf": "elf",
    "mcu-hex": "ihex", "bootloader-rpi": "rpi_eeprom",
    "full-flash": None,
}

# ---------------------------------------------------------------------------
# `file` description -> canonical. Ordered; first substring hit wins. `file`
# emits free text, so we match on stable phrases. "data" alone => unknown.
# ---------------------------------------------------------------------------
FILE_RULES = [
    ("squashfs", "squashfs"),
    ("erofs", "erofs"),
    ("u-boot legacy uimage", "uimage"), ("uimage", "uimage"),
    ("device tree blob", "dtb"), ("flattened device tree", "dtb"),
    ("intel hex", "ihex"), ("hexadecimal object", "ihex"),
    ("android bootimg", "android_boot"), ("android boot", "android_boot"),
    ("android sparse", "android_sparse"), ("sparse image", "android_sparse"),
    ("jffs2", "jffs2"),
    ("ubifs", "ubi"), ("ubi image", "ubi"),
    ("yaffs", "yaffs2"),
    ("romfs", "romfs"),
    ("cramfs", "cramfs"),
    ("f2fs", "f2fs"),
    ("exfat", "exfat"),
    ("ntfs", "ntfs"),
    ("iso 9660", "iso9660"), ("iso9660", "iso9660"),
    ("btrfs", "btrfs"),
    ("xfs filesystem", "xfs"),
    ("hfs+", "hfsplus"), ("hierarchical file system", "hfsplus"),
    ("ext2 filesystem", "ext"), ("ext3 filesystem", "ext"),
    ("ext4 filesystem", "ext"), ("ext2/ext3", "ext"),
    ("linux rev", "ext"),  # "Linux rev 1.0 ext4 filesystem data"
    ("elf ", "elf"), ("elf 32", "elf"), ("elf 64", "elf"),
    ("zip archive", "zip"), ("jar", "zip"),
    ("gzip compressed", "gzip"),
    ("xz compressed", "xz"),
    ("zstandard", "zstd"),
    ("lz4 compressed", "lz4"), ("lz4 frame", "lz4"),
    ("bzip2 compressed", "bzip2"),
    ("7-zip", "7z"),
    ("rar archive", "rar"),
    ("posix tar", "tar"), ("tar archive", "tar"),
    ("cpio archive", "cpio"),
    ("pdf document", "pdf"),
    ("png image", "png"),
    ("jpeg image", "jpeg"),
    ("gif image", "gif"),
    ("bitmap", "bmp"),
    ("raspberry pi eeprom", "rpi_eeprom"),
    ("openssh private key", "private_key"), ("private key", "private_key"),
    ("pem certificate", "certificate"), ("certificate", "certificate"),
    # --- general formats (--broad / format-corpus comparison) -------------
    ("jpeg 2000", "jp2k"),
    ("tiff image", "tiff"), ("webp", "webp"),
    ("svg", "svg"),
    ("epub document", "epub"), ("mobipocket", "mobipocket"),
    ("iso media", "isomedia"), ("quicktime", "isomedia"), ("mp4", "isomedia"),
    ("matroska", "matroska"), ("webm", "matroska"),
    ("microsoft word 2007", "docx"), ("microsoft excel 2007", "xlsx"),
    ("microsoft powerpoint 2007", "pptx"),
    ("word 2007+", "docx"), ("excel 2007+", "xlsx"), ("powerpoint 2007+", "pptx"),
    ("composite document", "msoffice"), ("cdfv2", "msoffice"),
    ("microsoft ooxml", "ooxml"), ("opendocument", "opendocument"),
    ("git index", "git"), ("git pack", "git"),
    ("microsoft access", "access"), ("wordperfect", "wordperfect"),
    ("apple desktop services", "dsstore"), ("indesign", "indesign"),
    ("aportisdoc", "palmdoc"), ("palmdoc", "palmdoc"),
    ("microsoft reader ebook", "ebook"), ("bbeb ebook", "ebook"),
    ("rich text format", "rtf"),
    ("flac audio", "flac"), ("ogg data", "ogg"),
    ("mpeg adts", "mp3"), ("audio file with id3", "mp3"),
    ("wave audio", "wav"), ("avi", "avi"),
    ("xml 1.0 document", "xml"), ("xml document", "xml"),
    ("html document", "html"),
    ("ascii text", "text"), ("unicode text", "text"), ("utf-8 unicode", "text"),
    ("iso-8859 text", "text"),
]


def file_verdict(path, timeout):
    """Return (top, raw, unmapped, all_types). `file` gives one whole-file
    verdict, so all_types is just {top}."""
    try:
        r = subprocess.run(["file", "-b", path], capture_output=True,
                           timeout=timeout, text=True, errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        return "unknown", "TIMEOUT/ERR", None, set()
    desc = (r.stdout or "").strip()
    low = desc.lower()
    if low.startswith("data") or low in ("empty", ""):
        return "unknown", desc, None, set()
    for needle, typ in FILE_RULES:
        if needle in low:
            c = canon(typ)
            return c, desc, None, {c}
    return "unknown", desc, desc, set()  # third item = unmapped raw string


def _binwalk_top(file_map):
    """The whole-file verdict = the signature at offset 0.

    binwalk's file_map also lists every mid-file match (embedded strings,
    crc32/aes constants, a copyright banner), which is "content found inside",
    not "what this file is". So the top-type verdict is the offset-0 entry;
    if binwalk matched nothing at the start, it offered no whole-file ID.
    Same rule is applied to moria for a symmetric comparison.
    """
    if not file_map:
        return None
    at0 = [e for e in file_map if e.get("offset", -1) == 0]
    if not at0:
        return None
    return max(at0, key=lambda e: e.get("confidence", 0))


def binwalk_verdict(path, timeout):
    """Return (top, raw, unmapped, all_types).

    top = canonical offset-0 verdict (what binwalk leads with);
    all_types = every canonical type binwalk matched anywhere (for GT detection).
    """
    try:
        r = subprocess.run(["binwalk", "-q", "-l", "-", path],
                           capture_output=True, timeout=timeout, text=True,
                           errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        return "unknown", "TIMEOUT/ERR", None, set()
    try:
        doc = json.loads(r.stdout)
        fm = doc[0]["Analysis"]["file_map"] if doc else []
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        return "unknown", "PARSE-ERR", None, set()
    all_types = {canon(e.get("name", "")) for e in fm}
    top = _binwalk_top(fm)
    if top is None:
        return "unknown", None, None, all_types
    name = top.get("name", "")
    raw = f"{name} (conf {top.get('confidence')})"
    # unmapped = the raw name if not in our family map (so the normalizer can
    # be extended for a token we didn't anticipate).
    return canon(name), raw, (name if name not in FAMILY else None), all_types


def unblob_verdict(path, timeout):
    # unblob has no stable one-shot "identify" JSON in older versions; use its
    # report if present. Optional tool — only called when on PATH.
    try:
        r = subprocess.run(["unblob", "--report", "-", "--dry-run", path],
                           capture_output=True, timeout=timeout, text=True,
                           errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        return "unknown", "TIMEOUT/ERR", None, set()
    # Best-effort: scan stdout for a known handler name. unblob emits chunk
    # handler ids like "squashfs_v4_le", "cpio_*", etc.
    out = (r.stdout or "") + (r.stderr or "")
    low = out.lower()
    hits = {canon(tok) for tok in FAMILY if tok in low}
    top = next(iter(hits)) if hits else "unknown"
    return top, (out[:80] if out else None), None, hits


def moria_verdict(path, timeout, broad=False):
    cmd = [MORIA, "-j", "--sigs", SIGS]  # -j: human view is the default now
    if broad:
        cmd.append("--broad")
    cmd.append(path)
    try:
        r = subprocess.run(cmd, capture_output=True,
                           timeout=timeout, text=True, errors="replace")
        doc = json.loads(r.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return "unknown", "TIMEOUT/ERR", None, set()
    except (json.JSONDecodeError, ValueError):
        return "unknown", "PARSE-ERR", None, set()
    findings = doc.get("findings", [])
    all_types = {canon(f.get("type", "")) for f in findings}
    assess = doc.get("assessment")
    # Symmetric with binwalk: the top-type verdict is the offset-0 finding.
    at0 = [f for f in findings if f.get("offset") == 0]
    if not at0:
        return "unknown", (assess or None), assess, all_types
    best = max(at0, key=lambda f: f.get("confidence", 0))
    raw = f"{best['type']} (conf {best.get('confidence')}, {best.get('confidence_tier')})"
    return canon(best["type"]), raw, None, all_types


def gather_files(corpus, categories, per_cat, max_bytes, recursive=False):
    """Yield (category, path) tuples.

    Default: one level — files directly under each category dir (the corpus shape,
    category dir = ground-truth type). With recursive=True (format-corpus and
    other theme-organized trees): walk all files; the category label is the
    top-level subdir name, used only for grouping the report (no type GT)."""
    out = []
    per = defaultdict(int)
    if recursive:
        for dirpath, _dirs, names in sorted(os.walk(corpus)):
            rel = os.path.relpath(dirpath, corpus)
            cat = rel.split(os.sep)[0] if rel != "." else "(root)"
            if categories and cat not in categories:
                continue
            for name in sorted(names):
                p = os.path.join(dirpath, name)
                if not os.path.isfile(p) or os.path.islink(p):
                    continue
                if os.path.getsize(p) > max_bytes:
                    continue
                if per_cat and per[cat] >= per_cat:
                    continue
                per[cat] += 1
                out.append((cat, p))
        return out
    for cat in sorted(os.listdir(corpus)):
        d = os.path.join(corpus, cat)
        if not os.path.isdir(d):
            continue
        if categories and cat not in categories:
            continue
        files = [os.path.join(d, f) for f in sorted(os.listdir(d))
                 if os.path.isfile(os.path.join(d, f))]
        files = [f for f in files if os.path.getsize(f) <= max_bytes]
        if per_cat:
            files = files[:per_cat]
        for f in files:
            out.append((cat, f))
    return out


def run_one(cat, path, tools, timeout, broad=False):
    row = {"cat": cat, "path": path,
           "gt": GROUND_TRUTH.get(cat, "unknown")}
    m, mraw, munmapped, mall = moria_verdict(path, timeout, broad)
    row["moria"] = m
    row["moria_raw"] = mraw
    row["moria_all"] = sorted(mall)
    if "file" in tools:
        f, fraw, funmapped, fall = file_verdict(path, timeout)
        row["file"] = f
        row["file_raw"] = fraw
        row["file_unmapped"] = funmapped
        row["file_all"] = sorted(fall)
    if "binwalk" in tools:
        b, braw, bunmapped, ball = binwalk_verdict(path, timeout)
        row["binwalk"] = b
        row["binwalk_raw"] = braw
        row["binwalk_unmapped"] = bunmapped
        row["binwalk_all"] = sorted(ball)
    if "unblob" in tools:
        u, uraw, _, uall = unblob_verdict(path, timeout)
        row["unblob"] = u
        row["unblob_raw"] = uraw
        row["unblob_all"] = sorted(uall)
    return row


def bucket(m, x):
    """Group one moria answer and one other program's answer."""
    if m == x:
        return "agree"
    if m != "unknown" and x == "unknown":
        return "moria_only"
    if m == "unknown" and x != "unknown":
        return "tool_only"
    return "mismatch"


def display_path(path, corpus):
    """Shorten a path by showing it from the test collection's main folder."""
    try:
        return os.path.relpath(path, corpus)
    except ValueError:
        return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=os.environ.get("MORIA_CORPUS", "corpus"),
                    help="folder of test files grouped by expected type")
    ap.add_argument("--out", default=os.path.join(HERE, "..", "diff-report"),
                    help="folder for the comparison report")
    ap.add_argument("--per-cat", type=int, default=0,
                    help="maximum files from each group (0 = all)")
    ap.add_argument("--max-bytes", type=int, default=2 * 1024**3,
                    help="skip files larger than this (default 2 GiB)")
    ap.add_argument("--timeout", type=int, default=180,
                    help="maximum seconds to wait for each program")
    ap.add_argument("--workers", type=int, default=4,
                    help="number of files to check at the same time")
    ap.add_argument("--categories", default="",
                    help="comma-separated list of groups to include")
    ap.add_argument("--no-binwalk", action="store_true",
                    help="do not compare with binwalk")
    ap.add_argument("--no-file", action="store_true",
                    help="do not compare with file")
    ap.add_argument("--broad", action="store_true",
                    help="pass --broad to moria (check about 2,500 more file types)")
    ap.add_argument("--recursive", action="store_true",
                    help="check all files under the selected folder; use each top-level "
                         "folder only to group the report")
    args = ap.parse_args()

    if not os.path.exists(MORIA):
        sys.exit(f"moria binary not found at {MORIA} (build it first)")
    if not os.path.isdir(args.corpus):
        sys.exit(f"test-file folder not found: {args.corpus}")

    tools = ["moria"]
    if not args.no_file and shutil.which("file"):
        tools.append("file")
    if not args.no_binwalk and shutil.which("binwalk"):
        tools.append("binwalk")
    if shutil.which("unblob"):
        tools.append("unblob")

    cats = set(c for c in args.categories.split(",") if c) or None
    work = gather_files(args.corpus, cats, args.per_cat, args.max_bytes, args.recursive)
    print(f"tools: {', '.join(tools)}{'  [moria --broad]' if args.broad else ''}")
    print(f"test files: {args.corpus}  ({len(work)} files)")
    if len(work) == 0:
        sys.exit("no samples to scan")

    rows = []
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(run_one, cat, path, tools, args.timeout, args.broad)
                for cat, path in work]
        for fut in futs:
            rows.append(fut.result())
            done += 1
            if done % 25 == 0 or done == len(work):
                print(f"  scanned {done}/{len(work)}", file=sys.stderr)

    incumbents = [t for t in tools if t != "moria"]

    # Per-tool agreement buckets vs moria.
    buckets = {t: defaultdict(list) for t in incumbents}
    for r in rows:
        for t in incumbents:
            buckets[t][bucket(r["moria"], r[t])].append(r)

    # Ground-truth scoreboard, per category, per tool. A tool is credited when
    # the labeled type appears anywhere in its findings (detection), matching
    # accuracy.py's convention — a padded image whose fs starts past offset 0
    # is still a detection, not a miss.
    def detects(r, tool, gt):
        return gt in set(r.get(tool + "_all", []))

    gt_rows = [r for r in rows if r["gt"] not in (None, "unknown")]
    scoreboard = defaultdict(lambda: defaultdict(lambda: [0, 0]))  # cat->tool->[hit,total]
    for r in gt_rows:
        gt = r["gt"]
        for t in tools:
            hit, tot = scoreboard[r["cat"]][t]
            scoreboard[r["cat"]][t] = [hit + (1 if detects(r, t, gt) else 0), tot + 1]

    # moria misses (moria doesn't detect gt at all) and wins (moria detects gt,
    # some incumbent doesn't). Detection-based, so offset>0 IDs count.
    misses, wins, not_top = [], [], []
    for r in gt_rows:
        gt = r["gt"]
        inc_ok = {t: detects(r, t, gt) for t in incumbents}
        if not detects(r, "moria", gt):
            r["_inc_ok"] = inc_ok
            misses.append(r)
        else:
            wrong = [t for t in incumbents if not inc_ok[t]]
            if wrong:
                r["_inc_wrong"] = wrong
                wins.append(r)
            # moria detected gt but its offset-0 top verdict is something else
            # (padded/multi-part image) — informative, not a miss.
            if r["moria"] != gt:
                not_top.append(r)

    # Unmapped raw verdict tokens (so the normalizer can be extended).
    unmapped = defaultdict(set)
    for r in rows:
        if r.get("file_unmapped"):
            unmapped["file"].add(r["file_unmapped"])
        if r.get("binwalk_unmapped"):
            unmapped["binwalk"].add(r["binwalk_unmapped"])

    # ----------------------------------------------------------------- report
    os.makedirs(args.out, exist_ok=True)
    md = []
    W = md.append
    W("# moria file-type comparison report\n")
    W(f"- programs: {', '.join(tools)}")
    W(f"- test-file folder: `{args.corpus}`")
    W(f"- files: {len(rows)}  (expected type known: {len(gt_rows)})")
    W(f"- largest file: {args.max_bytes} bytes  files per group: {args.per_cat or 'all'}")
    W("- **main answer = the type each program finds at starting byte 0.** "
      "Matches later in the file are not counted as the main answer. A program "
      "with no match at byte 0 gives an unknown answer. Equivalent type names "
      "are grouped together "
      "(squashfs==squashfs_legacy, ubi==ubifs, fat==fat32, ext2/3/4==ext, "
      "dtb==fit, ...) before comparison.\n")

    W("## Agreement with moria's main answer\n")
    W("| other program | agree | only moria finds a type | only other program finds a type | different types |")
    W("|---|---:|---:|---:|---:|")
    for t in incumbents:
        b = buckets[t]
        W(f"| {t} | {len(b['agree'])} | {len(b['moria_only'])} "
          f"| {len(b['tool_only'])} | {len(b['mismatch'])} |")
    W("")
    W("- **Only moria finds a type:** moria names the whole file while the other "
      "program says unknown or data.")
    W("- **Only the other program finds a type:** the other program names the "
      "whole file while moria does not. moria may still find that type later in "
      "the file.")
    W("- **Different types:** both programs name the whole file, but their answers differ.\n")

    W("## Expected file types found, by group\n")
    W("A program gets credit when the expected type appears anywhere in its "
      "results, even if it starts later than byte 0.\n")
    hdr = "| category | n | " + " | ".join(tools) + " |"
    W(hdr)
    W("|---|---:|" + "---:|" * len(tools))
    totals = {t: [0, 0] for t in tools}
    for cat in sorted(scoreboard):
        n = scoreboard[cat][tools[0]][1]
        cells = []
        for t in tools:
            hit, tot = scoreboard[cat][t]
            totals[t][0] += hit
            totals[t][1] += tot
            cells.append(f"{100*hit/tot:.0f}%" if tot else "--")
        W(f"| {cat} | {n} | " + " | ".join(cells) + " |")
    tcells = []
    for t in tools:
        hit, tot = totals[t]
        tcells.append(f"{100*hit/tot:.0f}%" if tot else "--")
    W(f"| **overall** | {totals[tools[0]][1]} | " + " | ".join(tcells) + " |")
    W("")

    # Compare every type reported by `file` with moria's matches anywhere in the
    # same file. This is useful when the test folders do not name expected types.
    if "file" in incumbents:
        by_ftype = defaultdict(lambda: [0, 0, []])  # ftype -> [detected, total, miss_paths]
        for r in rows:
            ft_ = r.get("file")
            if ft_ in (None, "unknown", "text"):
                continue  # text = moria out of scope (binary/firmware identifier)
            rec = by_ftype[ft_]
            rec[1] += 1
            if ft_ in set(r.get("moria_all", [])):
                rec[0] += 1
            else:
                rec[2].append(r)
        det_tot = sum(v[0] for v in by_ftype.values())
        all_tot = sum(v[1] for v in by_ftype.values())
        W("## File types found by both moria and `file`\n")
        W("For each non-text type reported by `file`, this section checks whether "
          "moria finds the same type anywhere in the file. A match may start after "
          "byte 0. Plain text is excluded because moria checks binary and firmware "
          "files.\n")
        if all_tot:
            W(f"- **moria detects {det_tot}/{all_tot} "
              f"({100*det_tot/all_tot:.1f}%) of the non-text types reported by `file`.**\n")
        W("| file type | n | moria detects | notes |")
        W("|---|---:|---:|---|")
        for ft_ in sorted(by_ftype, key=lambda k: -by_ftype[k][1]):
            det, tot, _ = by_ftype[ft_]
            note = ""
            if det < tot and ft_ in ("epub", "docx", "xlsx", "pptx",
                                     "opendocument", "ooxml"):
                note = "moria finds ZIP but has no separate rule for this document type"
            W(f"| {ft_} | {tot} | {det}/{tot} | {note} |")
        W("")
        # Types reported by `file` that moria never finds.
        gaps = {ft_: v for ft_, v in by_ftype.items() if v[0] == 0}
        if gaps:
            W("### File types that may need new moria recognition rules\n")
            for ft_ in sorted(gaps, key=lambda k: -gaps[k][1]):
                paths = [display_path(r["path"], args.corpus) for r in gaps[ft_][2][:3]]
                W(f"- **{ft_}** ({gaps[ft_][1]}): e.g. " +
                  ", ".join(f"`{p}`" for p in paths))
            W("")

    W(f"## Expected types moria misses ({len(misses)})\n")
    W("moria does not find the expected type in these files. `Other programs "
      "that find it` shows which comparison programs agree with the expected label.\n")
    misses.sort(key=lambda r: r["cat"])
    for r in misses:
        right = [t for t, ok in r["_inc_ok"].items() if ok]
        W(f"- `{display_path(r['path'], args.corpus)}` expected=**{r['gt']}** "
          f"moria=**{r['moria']}** ({r.get('moria_raw')}) "
          f"| other programs that find it: {', '.join(right) or 'none'}")
    if not misses:
        W("_none._")
    W("")

    W(f"## Expected type found later in the file ({len(not_top)})\n")
    W("moria found the expected type after byte 0, so it gave a different type as "
      "the main answer for the whole file. This often happens when a file system "
      "starts after a device header or when one file contains several parts.\n")
    not_top.sort(key=lambda r: r["cat"])
    for r in not_top:
        W(f"- `{display_path(r['path'], args.corpus)}` expected=**{r['gt']}** found; "
          f"main answer={r['moria']} ({r.get('moria_raw')})")
    if not_top:
        pass
    else:
        W("_none._")
    W("")

    W(f"## Expected types moria finds and another program misses ({len(wins)})\n")
    wins.sort(key=lambda r: r["cat"])
    for r in wins:
        det = []
        for t in r["_inc_wrong"]:
            det.append(f"{t}={r[t]} ({r.get(t+'_raw')})")
        W(f"- `{display_path(r['path'], args.corpus)}` expected=**{r['gt']}** "
          f"moria finds the expected type | other results: {'; '.join(det)}")
    if not wins:
        W("_none._")
    W("")

    # Different answers for files whose expected type is not known.
    nogt_mismatch = []
    for r in rows:
        if r["gt"] not in (None, "unknown"):
            continue
        for t in incumbents:
            if bucket(r["moria"], r[t]) == "mismatch":
                nogt_mismatch.append((r, t))
    W(f"## Different answers for files without an expected type ({len(nogt_mismatch)})\n")
    W("moria and another program gave different main answers for these files. "
      "This is common when one firmware file contains several formats.\n")
    for r, t in nogt_mismatch[:60]:
        W(f"- `{display_path(r['path'], args.corpus)}` moria={r['moria']} "
          f"vs {t}={r[t]}")
    if len(nogt_mismatch) > 60:
        W(f"- ... and {len(nogt_mismatch)-60} more (see JSON)")
    if not nogt_mismatch:
        W("_none._")
    W("")

    if any(unmapped.values()):
        W("## Answers that are not yet grouped under a shared file-type name\n")
        for t, toks in unmapped.items():
            if toks:
                W(f"- **{t}**: " + ", ".join(f"`{x}`" for x in sorted(toks)))
        W("")

    report_md = os.path.join(args.out, "report.md")
    report_json = os.path.join(args.out, "report.json")
    with open(report_md, "w") as fh:
        fh.write("\n".join(md))
    with open(report_json, "w") as fh:
        json.dump({"tools": tools, "corpus": args.corpus, "rows": rows},
                  fh, indent=1, default=list)

    # ------------------------------------------------------------ terminal tail
    print("\n" + "\n".join(md[:2]))
    print("\nagreement with moria:")
    for t in incumbents:
        b = buckets[t]
        print(f"  {t:<8} agree={len(b['agree'])} moria_only={len(b['moria_only'])} "
              f"tool_only={len(b['tool_only'])} mismatch={len(b['mismatch'])}")
    print("\nexpected file types found:")
    for t in tools:
        hit, tot = totals[t]
        print(f"  {t:<8} {100*hit/tot:.1f}%  ({hit}/{tot})" if tot else f"  {t}: --")
    print(f"\nexpected types moria misses: {len(misses)}   "
          f"types another program misses: {len(wins)}   "
          f"expected type found later: {len(not_top)}")
    print(f"\nreport: {report_md}\n        {report_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

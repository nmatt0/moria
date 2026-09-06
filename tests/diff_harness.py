#!/usr/bin/env python3
"""Differential identification harness: moria vs file / binwalk / unblob.

Runs each installed tool on every corpus sample, normalizes each tool's
top-type verdict onto moria's type vocabulary, diffs the verdicts, and emits a
categorized disagreement report. This is a triage aid, NOT a hard gate: it
surfaces (a) moria's real misses/mislabels and (b) cases where moria is right
and an incumbent is wrong.

Ground truth: the corpus groups samples into category directories (fs-squashfs,
uimage, dtb, ...); that directory IS the labeled type. Container categories
(full-flash) have no single top type, so they are scored for agreement only,
not correctness.

The report (which echoes corpus filenames) is written to a gitignored output
dir (default: diff-report/) so nothing from the corpus lands in the tree.

Usage:
  tests/diff_harness.py [--corpus DIR] [--out DIR] [--per-cat N]
                        [--max-bytes N] [--timeout S] [--workers N]
                        [--categories a,b,c] [--no-binwalk] [--no-file]

Point --corpus at a local firmware corpus (subdirs name the expected type).
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
# Type vocabulary: canonical families. Every tool's raw verdict is folded to a
# canonical token so squashfs == squashfs_legacy, ubi == ubifs, fat == fat32,
# etc. all count as agreement. The canonical token is the family key.
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
    """Compare moria (m) vs incumbent (x); both canonical."""
    if m == x:
        return "agree"
    if m != "unknown" and x == "unknown":
        return "moria_only"
    if m == "unknown" and x != "unknown":
        return "tool_only"
    return "mismatch"


def redact(path, corpus):
    """Path relative to corpus root (still gitignored output, but tidy)."""
    try:
        return os.path.relpath(path, corpus)
    except ValueError:
        return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=os.environ.get("MORIA_CORPUS", "corpus"))
    ap.add_argument("--out", default=os.path.join(HERE, "..", "diff-report"))
    ap.add_argument("--per-cat", type=int, default=0,
                    help="cap files per category (0 = all)")
    ap.add_argument("--max-bytes", type=int, default=2 * 1024**3,
                    help="skip samples larger than this (default 2 GiB)")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--categories", default="",
                    help="comma-separated category allowlist")
    ap.add_argument("--no-binwalk", action="store_true")
    ap.add_argument("--no-file", action="store_true")
    ap.add_argument("--broad", action="store_true",
                    help="pass --broad to moria (load ~2.5k generated general-format sigs)")
    ap.add_argument("--recursive", action="store_true",
                    help="walk all files under corpus (theme-organized trees like "
                         "format-corpus); category = top-level subdir, no type GT")
    args = ap.parse_args()

    if not os.path.exists(MORIA):
        sys.exit(f"moria binary not found at {MORIA} (build it first)")
    if not os.path.isdir(args.corpus):
        sys.exit(f"corpus dir not found: {args.corpus}")

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
    print(f"corpus: {args.corpus}  ({len(work)} samples)")
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
    W("# moria differential identification report\n")
    W(f"- tools: {', '.join(tools)}")
    W(f"- corpus: `{args.corpus}`")
    W(f"- samples: {len(rows)}  (ground-truth-labeled: {len(gt_rows)})")
    W(f"- max-bytes: {args.max_bytes}  per-cat: {args.per_cat or 'all'}")
    W("- **top verdict = the type each tool assigns at offset 0** (the whole-file "
      "identity). Mid-file matches — embedded strings, crc/aes constants, a nested "
      "blob — are not counted as a verdict; a tool with nothing at offset 0 gave "
      "no whole-file ID (unknown). Verdicts are folded to canonical families "
      "(squashfs==squashfs_legacy, ubi==ubifs, fat==fat32, ext2/3/4==ext, "
      "dtb==fit, ...) before diffing.\n")

    W("## Agreement with moria (top verdict, canonical)\n")
    W("| incumbent | agree | moria-only IDs | tool-only IDs | mismatch |")
    W("|---|---:|---:|---:|---:|")
    for t in incumbents:
        b = buckets[t]
        W(f"| {t} | {len(b['agree'])} | {len(b['moria_only'])} "
          f"| {len(b['tool_only'])} | {len(b['mismatch'])} |")
    W("")
    W("- **moria-only IDs**: moria names a type at offset 0 where the incumbent "
      "says unknown/data.")
    W("- **tool-only IDs**: the incumbent names a type at offset 0 where moria's "
      "offset-0 verdict is unknown. This is a *top-verdict* axis: moria may still "
      "detect the type past offset 0 (see the misses and padded/multi-part "
      "sections for true non-detection).")
    W("- **mismatch**: both name a type at offset 0 but they differ.\n")

    W("## Ground-truth scoreboard (labeled type detected, by category)\n")
    W("A tool is credited when the labeled type appears anywhere in its findings "
      "(detection), not only at offset 0 — so a padded image counts.\n")
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

    # Detection vs `file` as reference oracle. For a corpus with no ground-truth
    # dirs (format-corpus), `file` is the authoritative general-format labeler;
    # this answers "what does file identify that moria does not detect anywhere".
    # Detection-based (not offset-0), so e.g. a PDF whose %PDF- header sits at
    # offset 1 behind a leading space counts as detected.
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
        W("## Detection vs `file` (file as reference oracle)\n")
        W("For every file `file` gives a specific type (plain text excluded — moria "
          "is a binary/firmware identifier, not a text classifier), does moria detect "
          "that type anywhere in its findings? Detection-based, so an offset>0 header "
          "counts.\n")
        if all_tot:
            W(f"- **moria detects {det_tot}/{all_tot} "
              f"({100*det_tot/all_tot:.1f}%) of file's non-text verdicts.**\n")
        W("| file type | n | moria detects | notes |")
        W("|---|---:|---:|---|")
        for ft_ in sorted(by_ftype, key=lambda k: -by_ftype[k][1]):
            det, tot, _ = by_ftype[ft_]
            note = ""
            if det < tot and ft_ in ("epub", "docx", "xlsx", "pptx",
                                     "opendocument", "ooxml"):
                note = "moria sees the zip container (no per-document sig)"
            W(f"| {ft_} | {tot} | {det}/{tot} | {note} |")
        W("")
        # The genuine gaps: file's non-text types moria detects in 0 cases.
        gaps = {ft_: v for ft_, v in by_ftype.items() if v[0] == 0}
        if gaps:
            W("### moria detects none of these `file` types (candidate sig gaps)\n")
            for ft_ in sorted(gaps, key=lambda k: -gaps[k][1]):
                paths = [redact(r["path"], args.corpus) for r in gaps[ft_][2][:3]]
                W(f"- **{ft_}** ({gaps[ft_][1]}): e.g. " +
                  ", ".join(f"`{p}`" for p in paths))
            W("")

    W(f"## moria misses ({len(misses)}) — real gaps/mislabels, prioritized\n")
    W("moria does not detect the labeled type at all. `correct incumbents` are "
      "the reference to chase (none => the corpus label itself is suspect).\n")
    misses.sort(key=lambda r: r["cat"])
    for r in misses:
        right = [t for t, ok in r["_inc_ok"].items() if ok]
        W(f"- `{redact(r['path'], args.corpus)}` gt=**{r['gt']}** "
          f"moria=**{r['moria']}** ({r.get('moria_raw')}) "
          f"| correct incumbents: {', '.join(right) or 'none'}")
    if not misses:
        W("_none._")
    W("")

    W(f"## moria detects but does not lead with ({len(not_top)}) — padded/multi-part\n")
    W("moria found the labeled type past offset 0 (leading header, NVRAM prefix, "
      "or a multi-part MTD block); the offset-0 top verdict is something else. "
      "Not a miss — often moria is more precise about where the fs starts.\n")
    not_top.sort(key=lambda r: r["cat"])
    for r in not_top:
        W(f"- `{redact(r['path'], args.corpus)}` gt=**{r['gt']}** detected; "
          f"top verdict={r['moria']} ({r.get('moria_raw')})")
    if not_top:
        pass
    else:
        W("_none._")
    W("")

    W(f"## moria wins ({len(wins)}) — moria right, an incumbent wrong\n")
    W("The credibility story: moria's precise verdict beats an incumbent.\n")
    wins.sort(key=lambda r: r["cat"])
    for r in wins:
        det = []
        for t in r["_inc_wrong"]:
            det.append(f"{t}={r[t]} ({r.get(t+'_raw')})")
        W(f"- `{redact(r['path'], args.corpus)}` gt=**{r['gt']}** "
          f"moria correct | wrong: {'; '.join(det)}")
    if not wins:
        W("_none._")
    W("")

    # Unresolved mismatches without ground truth (container/full-flash etc.)
    nogt_mismatch = []
    for r in rows:
        if r["gt"] not in (None, "unknown"):
            continue
        for t in incumbents:
            if bucket(r["moria"], r[t]) == "mismatch":
                nogt_mismatch.append((r, t))
    W(f"## Unlabeled mismatches ({len(nogt_mismatch)}) — no ground truth\n")
    W("Container/unlabeled samples where moria and an incumbent name different "
      "top types (expected for multi-format images; skim for surprises).\n")
    for r, t in nogt_mismatch[:60]:
        W(f"- `{redact(r['path'], args.corpus)}` moria={r['moria']} "
          f"vs {t}={r[t]}")
    if len(nogt_mismatch) > 60:
        W(f"- ... and {len(nogt_mismatch)-60} more (see JSON)")
    if not nogt_mismatch:
        W("_none._")
    W("")

    if any(unmapped.values()):
        W("## Unmapped incumbent verdicts (extend the normalizer)\n")
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
    print("\nagreement vs moria:")
    for t in incumbents:
        b = buckets[t]
        print(f"  {t:<8} agree={len(b['agree'])} moria_only={len(b['moria_only'])} "
              f"tool_only={len(b['tool_only'])} mismatch={len(b['mismatch'])}")
    print("\nground-truth detection accuracy:")
    for t in tools:
        hit, tot = totals[t]
        print(f"  {t:<8} {100*hit/tot:.1f}%  ({hit}/{tot})" if tot else f"  {t}: --")
    print(f"\nmoria misses: {len(misses)}   moria wins: {len(wins)}   "
          f"detected-not-top: {len(not_top)}")
    print(f"\nreport: {report_md}\n        {report_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

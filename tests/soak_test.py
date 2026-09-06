#!/usr/bin/env python3
"""Big real-data soak test: run moria identify + extract + carve over a broad,
size-tiered sample of a local firmware corpus and flag anomalies (crashes,
hangs, non-JSON output, extraction failures, carve-fidelity breaks).

Not a pass/fail gate — a bug-finding harness. Output (which echoes corpus
filenames) goes to the gitignored diff-report/soak/, never committed.

Small samples run under the ASan build (catches memory bugs); larger ones run
under the release build (speed). Extract/carve outputs are written to a scratch
dir and deleted after each sample unless an anomaly is found.

Usage: tests/soak_test.py [--per-cat N] [--max-mb N] [--corpus DIR] [--scratch DIR]
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REL = os.path.join(ROOT, "build", "moria")
ASAN = os.path.join(ROOT, "build-asan", "moria")

# size tiers (bytes)
ASAN_CAP = 32 * 1024 * 1024      # <= this -> ASan build, all 3 ops
MED_CAP = 256 * 1024 * 1024      # <= this -> release, all 3 ops
# > MED_CAP -> release, identify only (extract/carve skipped to bound runtime)

TIMEOUT_ID = 120
TIMEOUT_EX = 300
TIMEOUT_CV = 180


def die(m):
    print(m, file=sys.stderr)
    sys.exit(2)


def pick_samples(corpus, per_cat, max_bytes):
    """Diverse selection: up to per_cat files per category dir, smallest first
    (so the soak stays fast) but sample across the size range by taking a few
    larger ones too. Skips files over max_bytes."""
    picked = []
    for cat in sorted(os.listdir(corpus)):
        cdir = os.path.join(corpus, cat)
        if not os.path.isdir(cdir):
            continue
        files = []
        for name in os.listdir(cdir):
            p = os.path.join(cdir, name)
            if os.path.isfile(p):
                try:
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                if 0 < sz <= max_bytes:
                    files.append((sz, p))
        files.sort()
        if not files:
            continue
        # take the smallest (per_cat*3//4) plus a spread of larger ones
        n = min(per_cat, len(files))
        small = files[: (n * 3) // 4]
        rest = files[(n * 3) // 4 :]
        step = max(1, len(rest) // max(1, n - len(small)))
        large = rest[::step][: n - len(small)]
        for sz, p in small + large:
            picked.append((cat, p, sz))
    return picked


def run(cmd, timeout):
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr, time.time() - t0, False
    except subprocess.TimeoutExpired:
        return None, b"", b"", time.time() - t0, True


def crashed(rc):
    # negative rc = killed by signal; >=128 conventionally signal; ASan aborts 1
    return rc is None or rc < 0 or (rc is not None and rc >= 128)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-cat", type=int, default=12)
    ap.add_argument("--max-mb", type=int, default=400)
    ap.add_argument("--corpus", default=os.environ.get("MORIA_CORPUS", "corpus"))
    ap.add_argument("--scratch", default=None)
    args = ap.parse_args()

    if not os.path.exists(REL):
        die(f"release build missing: {REL}")
    asan_ok = os.path.exists(ASAN)
    if not asan_ok:
        print(f"note: ASan build missing ({ASAN}); running everything on release", file=sys.stderr)

    scratch = args.scratch or os.path.join(
        os.environ.get("TMPDIR", "/tmp"), f"moria-soak-{os.getpid()}")
    os.makedirs(scratch, exist_ok=True)
    outdir = os.path.join(ROOT, "diff-report", "soak")
    os.makedirs(outdir, exist_ok=True)
    logf = open(os.path.join(outdir, "soak.jsonl"), "w")

    samples = pick_samples(args.corpus, args.per_cat, args.max_mb * 1024 * 1024)
    print(f"selected {len(samples)} samples across "
          f"{len(set(c for c, _, _ in samples))} categories; scratch={scratch}")

    anomalies = []           # high-signal: crashes, hangs, bad output, fidelity breaks
    notes = []               # lower-signal: partials, misses, empty extracts
    stats = {"id": 0, "ex": 0, "cv": 0}

    def record(kind, cat, path, op, msg, extra=None):
        row = {"kind": kind, "cat": cat, "file": os.path.basename(path), "op": op, "msg": msg}
        if extra:
            row.update(extra)
        (anomalies if kind == "ANOMALY" else notes).append(row)
        logf.write(json.dumps(row) + "\n")
        logf.flush()
        tag = "!! ANOMALY" if kind == "ANOMALY" else "   note"
        print(f"{tag}  [{cat}] {os.path.basename(path)[:48]:48} {op:8} {msg}")

    for idx, (cat, path, sz) in enumerate(samples):
        moria = ASAN if (asan_ok and sz <= ASAN_CAP) else REL
        tier = "asan" if moria == ASAN else "rel"
        do_extract_carve = sz <= MED_CAP
        base = f"{idx:04d}"
        print(f"[{idx+1}/{len(samples)}] [{cat}] {os.path.basename(path)[:50]} "
              f"({sz//1024} KiB, {tier})")

        # ---- identify ----
        stats["id"] += 1
        rc, out, err, dt, to = run([moria, "-j", path], TIMEOUT_ID)
        errs = err.decode("replace", "ignore")
        if to:
            record("ANOMALY", cat, path, "identify", f"HANG >{TIMEOUT_ID}s")
        elif crashed(rc):
            record("ANOMALY", cat, path, "identify", f"CRASH rc={rc}",
                   {"stderr": errs[-800:]})
        else:
            try:
                doc = json.loads(out)
                nf = len(doc.get("findings", []))
                if nf == 0:
                    record("note", cat, path, "identify", "0 findings")
            except Exception as e:
                record("ANOMALY", cat, path, "identify", f"non-JSON stdout: {e}",
                       {"stdout_head": out[:200].decode('replace', 'ignore')})
            if "warning" in errs.lower():
                record("note", cat, path, "identify", "sig-load/other warning",
                       {"stderr": errs[-400:]})

        if not do_extract_carve:
            continue

        # ---- extract ----
        stats["ex"] += 1
        exd = os.path.join(scratch, base + ".ex")
        rc, out, err, dt, to = run([moria, "-e", "-C", exd, path], TIMEOUT_EX)
        errs = err.decode("replace", "ignore")
        ex_anom = False
        if to:
            record("ANOMALY", cat, path, "extract", f"HANG >{TIMEOUT_EX}s"); ex_anom = True
        elif crashed(rc):
            record("ANOMALY", cat, path, "extract", f"CRASH rc={rc}", {"stderr": errs[-800:]})
            ex_anom = True
        else:
            man = os.path.join(exd, "manifest.json")
            nfiles = 0
            if os.path.isdir(exd):
                for _, _, fs in os.walk(exd):
                    nfiles += len(fs)
            statuses = []
            capped = False
            cap_reason = ""
            if os.path.exists(man):
                try:
                    m = json.load(open(man))
                    statuses = [e.get("status", "") for e in m.get("extracted", [])]
                    capped = bool(m.get("capped"))
                    cap_reason = m.get("cap_reason", "")
                except Exception as e:
                    record("note", cat, path, "extract", f"manifest parse: {e}")
            bad = [s for s in statuses if s.startswith("error") or s == "partial"]
            if bad:
                from collections import Counter
                c = Counter(bad)
                record("note", cat, path, "extract",
                       "partial/error: " + ", ".join(f"{k}x{v}" for k, v in sorted(c.items())),
                       {"n_ok": sum(1 for s in statuses if s == "ok")})
            if capped:
                record("note", cat, path, "extract", f"capped: {cap_reason}")
            # a filesystem/container was identified but extraction produced nothing
            if statuses and nfiles == 0:
                record("note", cat, path, "extract", "manifest present but 0 files on disk")
        # ---- carve ----
        stats["cv"] += 1
        cvd = os.path.join(scratch, base + ".cv")
        rc, out, err, dt, to = run([moria, "-c", "-C", cvd, path], TIMEOUT_CV)
        errs = err.decode("replace", "ignore")
        cv_anom = False
        if to:
            record("ANOMALY", cat, path, "carve", f"HANG >{TIMEOUT_CV}s"); cv_anom = True
        elif crashed(rc):
            record("ANOMALY", cat, path, "carve", f"CRASH rc={rc}", {"stderr": errs[-800:]})
            cv_anom = True
        else:
            # carve fidelity: spot-check the first carved blob is byte-identical
            man = os.path.join(cvd, "manifest.json")
            if os.path.exists(man):
                try:
                    m = json.load(open(man))
                    fdata = open(path, "rb").read() if sz <= ASAN_CAP else None
                    for e in (m.get("carved") or [])[:1]:
                        blob = os.path.join(cvd, e["file"])
                        if fdata is not None and os.path.exists(blob):
                            b = open(blob, "rb").read()
                            if b != fdata[e["offset"]:e["offset"] + e["size"]]:
                                record("ANOMALY", cat, path, "carve",
                                       f"FIDELITY break on {e['file']}")
                                cv_anom = True
                except Exception as e:
                    record("note", cat, path, "carve", f"manifest parse: {e}")

        # cleanup unless something interesting happened
        for d in (exd, cvd):
            if os.path.isdir(d) and not (ex_anom or cv_anom):
                shutil.rmtree(d, ignore_errors=True)

    # ---- summary ----
    print("\n" + "=" * 70)
    print(f"ran identify x{stats['id']}, extract x{stats['ex']}, carve x{stats['cv']}")
    print(f"ANOMALIES: {len(anomalies)}   notes: {len(notes)}")
    summ = os.path.join(outdir, "summary.md")
    with open(summ, "w") as f:
        f.write(f"# moria soak — {len(samples)} samples, {time.strftime('%Y-%m-%d %H:%M')}\n\n")
        f.write(f"identify x{stats['id']}, extract x{stats['ex']}, carve x{stats['cv']}. "
                f"**{len(anomalies)} anomalies, {len(notes)} notes.**\n\n")
        f.write("## Anomalies (crashes / hangs / bad output / fidelity)\n\n")
        for a in anomalies:
            f.write(f"- **{a['op']}** [{a['cat']}] `{a['file']}` — {a['msg']}\n")
        if not anomalies:
            f.write("_none_\n")
        f.write("\n## Notes (partials / misses / warnings), grouped\n\n")
        by = {}
        for n in notes:
            by.setdefault((n["op"], n["msg"].split(":")[0]), []).append(n)
        for (op, msg), rows in sorted(by.items(), key=lambda kv: -len(kv[1])):
            f.write(f"- **{op} — {msg}**: {len(rows)}  "
                    f"(e.g. {', '.join(r['file'][:28] for r in rows[:4])})\n")
    print(f"summary -> {summ}\n         -> {os.path.join(outdir, 'soak.jsonl')}")
    print(f"scratch (anomaly repros kept): {scratch}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

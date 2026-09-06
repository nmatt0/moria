#!/usr/bin/env python3
"""Deterministic regression test: build synthetic samples, run moria, assert
each is identified as the expected type at or above the expected confidence.
Negatives (type None) must produce no finding of a known firmware/format type.

Exit status is nonzero on any failure. No external corpus required.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_samples  # noqa: E402

BIN = os.path.join(HERE, "..", "build", "moria")


def run(path):
    r = subprocess.run([BIN, "-j", path], capture_output=True, timeout=60)
    return json.loads(r.stdout)


def coverage_gate():
    """Every core signature (signatures/*.toml) must have a synthetic fixture,
    else be explicitly waived. Keeps the suite honest as signatures grow."""
    import glob
    import re
    waived = set()  # none currently — all core sigs have fixtures
    sig_names = set()
    for p in glob.glob(os.path.join(HERE, "..", "signatures", "*.toml")):
        m = re.search(r'(?m)^name\s*=\s*"([^"]+)"', open(p).read())
        if m:
            sig_names.add(m.group(1))
    covered = {t for _, _, t, _ in gen_samples.MANIFEST if t}
    missing = sig_names - covered - waived
    if missing:
        print(f"  COVERAGE GAP: core signatures with no fixture: {sorted(missing)}")
    return not missing


def sig_load_sanity():
    """All signature sets (core + firmware + generated via --broad) must load
    with zero warnings — a malformed .toml otherwise only surfaces at runtime."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".txt") as tf:
        tf.write(b"hello\n")
        tf.flush()
        r = subprocess.run([BIN, "-j", "--broad", tf.name], capture_output=True, timeout=60)
    warns = [ln for ln in r.stderr.decode(errors="replace").splitlines() if "warning" in ln.lower()]
    if warns:
        print(f"  SIGNATURE LOAD WARNINGS ({len(warns)}):")
        for w in warns[:5]:
            print(f"    {w}")
    return not warns


def list_members_check():
    """--list must enumerate real tar/zip members (names+sizes) without extracting."""
    import tarfile
    import tempfile
    import zipfile
    ok = True
    with tempfile.TemporaryDirectory() as d:
        # tar
        tp = os.path.join(d, "a.tar")
        with tarfile.open(tp, "w") as t:
            for name, data in [("etc/passwd", b"root:x:0:0\n"), ("bin/sh", b"\x7fELFxx")]:
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                import io
                t.addfile(ti, io.BytesIO(data))
        r = subprocess.run([BIN, "-j", "--list", tp], capture_output=True, timeout=30)
        fs = json.loads(r.stdout)["findings"]
        names = {m["name"] for f in fs if f["type"] == "tar" for m in f.get("members", [])}
        if not {"etc/passwd", "bin/sh"} <= names:
            print(f"  LIST tar: expected members missing, got {names}")
            ok = False
        # zip
        zp = os.path.join(d, "a.zip")
        with zipfile.ZipFile(zp, "w") as z:
            z.writestr("config.xml", b"<x/>")
            z.writestr("lib/app.so", b"\x7fELF")
        r = subprocess.run([BIN, "-j", "--list", zp], capture_output=True, timeout=30)
        fs = json.loads(r.stdout)["findings"]
        names = {m["name"] for f in fs if f["type"] == "zip" for m in f.get("members", [])}
        if not {"config.xml", "lib/app.so"} <= names:
            print(f"  LIST zip: expected members missing, got {names}")
            ok = False
    return ok


def main():
    if not os.path.exists(BIN):
        print(f"error: {BIN} not built", file=sys.stderr)
        return 2

    fails = []
    with tempfile.TemporaryDirectory() as d:
        for name, builder, expect_type, min_conf in gen_samples.MANIFEST:
            path = os.path.join(d, name)
            with open(path, "wb") as f:
                f.write(builder())
            doc = run(path)
            findings = doc["findings"]
            if expect_type is None:
                # Negative: no finding should claim a real format for this blob.
                got = [f["type"] for f in findings]
                status = "ok" if not got else f"UNEXPECTED {got}"
                if got:
                    fails.append((name, status))
            else:
                match = [f for f in findings if f["type"] == expect_type]
                if not match:
                    status = f"MISSING {expect_type} (got {[f['type'] for f in findings]})"
                    fails.append((name, status))
                elif max(f["confidence"] for f in match) < min_conf:
                    c = max(f["confidence"] for f in match)
                    status = f"LOW CONF {c} < {min_conf}"
                    fails.append((name, status))
                else:
                    status = f"ok ({expect_type} @ {max(f['confidence'] for f in match)})"
            print(f"  {'FAIL' if (name in [x[0] for x in fails]) else 'PASS'}  {name:22} {status}")

    print("-" * 60)
    cov_ok = coverage_gate()
    load_ok = sig_load_sanity()
    list_ok = list_members_check()
    if fails or not cov_ok or not load_ok or not list_ok:
        extra = []
        if not cov_ok:
            extra.append("coverage gap")
        if not load_ok:
            extra.append("sig-load warnings")
        if not list_ok:
            extra.append("--list broken")
        print(f"FAIL: {len(fails)}/{len(gen_samples.MANIFEST)} samples"
              f"{(' + ' + ', '.join(extra)) if extra else ''}")
        return 1
    print(f"PASS: all {len(gen_samples.MANIFEST)} samples; every core signature has a fixture; "
          f"all signature sets load clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())

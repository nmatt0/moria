#!/usr/bin/env python3
"""UPX-packed-executable detection regression.

Two layers:
  * Synthetic (always runs): a hand-built UPX PackHeader trailer (public header
    structure, no third-party payload) must identify as `upx` verified with the
    right format/method/version; zeroing the trailer magic must instead flag the
    ELF with the `upx-tampered-header` diagnostic and produce no `upx` finding.
  * Real (self-skips without the `upx` tool): pack a host ELF with several
    methods and confirm moria's format/method/checksum-verified read matches, and
    that a magic-tampered copy is flagged tampered.

Exit nonzero on any failure.
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")
sys.path.insert(0, HERE)
import gen_samples  # noqa: E402


def run(path):
    r = subprocess.run([MORIA, "-j", path], capture_output=True, timeout=60)
    return json.loads(r.stdout)


def findings(doc, typ):
    return [f for f in doc["findings"] if f["type"] == typ]


def all_diag_codes(doc):
    codes = {d.get("code") for d in doc.get("diagnostics", [])}
    for f in doc["findings"]:
        codes |= {d.get("code") for d in f.get("diagnostics", [])}
    return codes


def tamper_trailer(data):
    """Zero the trailing 'UPX!' PackHeader magic (the embedded/malware case)."""
    b = bytearray(data)
    m = b.rfind(b"UPX!")
    assert m >= 0
    b[m:m + 4] = b"\x00\x00\x00\x00"
    return bytes(b)


def check(cond, msg, fails):
    if not cond:
        fails.append(msg)
    return cond


def synthetic(fails):
    with tempfile.TemporaryDirectory() as d:
        # Clean: verified upx finding with format/method/version populated.
        p = os.path.join(d, "prog.upx")
        with open(p, "wb") as f:
            f.write(gen_samples.upx_packed())
        doc = run(p)
        ux = findings(doc, "upx")
        if check(len(ux) == 1, f"synthetic: expected 1 upx finding, got {len(ux)}", fails):
            u = ux[0]
            check(u["confidence"] == 99, f"synthetic: upx tier {u['confidence']} != 99", fails)
            check(u.get("arch") == "amd64", f"synthetic: arch {u.get('arch')} != amd64", fails)
            check(u.get("compression") == "NRV2B",
                  f"synthetic: method {u.get('compression')} != NRV2B", fails)
            check(u.get("version") == "4.24", f"synthetic: version {u.get('version')} != 4.24", fails)
        check(bool(findings(doc, "elf")), "synthetic: elf finding missing", fails)
        check("upx-tampered-header" not in all_diag_codes(doc),
              "synthetic: clean file wrongly flagged tampered", fails)

        # Tampered: no upx finding, elf carries the diagnostic.
        pt = os.path.join(d, "prog.tampered")
        with open(pt, "wb") as f:
            f.write(tamper_trailer(gen_samples.upx_packed()))
        doc = run(pt)
        check(not findings(doc, "upx"), "tampered: should have no verified upx finding", fails)
        check("upx-tampered-header" in all_diag_codes(doc),
              "tampered: upx-tampered-header diagnostic missing", fails)


def real(fails):
    upx = shutil.which("upx")
    src = shutil.which("true") or shutil.which("cat")
    if not upx or not src:
        print("  (upx tool or a small ELF not present, real-sample checks skipped)")
        return
    method_opt = {"NRV2B": [], "NRV2D": ["--nrv2d"], "NRV2E": ["--nrv2e"], "LZMA": ["--lzma"]}
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "base.elf")
        shutil.copy(src, base)
        for want, opt in method_opt.items():
            out = os.path.join(d, f"packed_{want}")
            r = subprocess.run([upx, "-q", "-f", *opt, "-o", out, base],
                               capture_output=True)
            if r.returncode != 0 or not os.path.exists(out):
                print(f"  (upx could not produce {want}, skipped)")
                continue
            doc = run(out)
            ux = findings(doc, "upx")
            if not check(len(ux) == 1, f"real[{want}]: expected 1 upx finding, got {len(ux)}", fails):
                continue
            u = ux[0]
            check(u["confidence"] == 99, f"real[{want}]: not verified ({u['confidence']})", fails)
            check(u.get("compression") == want,
                  f"real[{want}]: method {u.get('compression')} != {want}", fails)

            # Tamper the real sample's trailer magic -> flagged, not identified.
            with open(out, "rb") as f:
                data = f.read()
            pt = os.path.join(d, f"tampered_{want}")
            with open(pt, "wb") as f:
                f.write(tamper_trailer(data))
            doc = run(pt)
            check(not findings(doc, "upx"),
                  f"real[{want}] tampered: unexpected upx finding", fails)
            check("upx-tampered-header" in all_diag_codes(doc),
                  f"real[{want}] tampered: diagnostic missing", fails)
        print("  real-sample checks ran against the installed upx")


def negative(fails):
    # A normal ELF with a section-header table must never be probed as UPX.
    cat = shutil.which("cat") or shutil.which("true")
    if cat:
        doc = run(cat)
        check(not findings(doc, "upx"), "negative: real system ELF flagged upx", fails)
        check("upx-tampered-header" not in all_diag_codes(doc),
              "negative: real system ELF flagged tampered", fails)


def main():
    if not os.path.exists(MORIA):
        print(f"error: {MORIA} not built", file=sys.stderr)
        return 2
    fails = []
    synthetic(fails)
    real(fails)
    negative(fails)
    if fails:
        print("FAIL test_upx:")
        for m in fails:
            print("   ", m)
        return 1
    print("PASS test_upx (synthetic + real + negative)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

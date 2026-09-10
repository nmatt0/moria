#!/usr/bin/env python3
"""Check moria's results against a labeled collection of firmware files.

Each folder groups examples of one type, such as fs-squashfs, uimage, or dtb.
The folder name is the expected type. The check runs moria on each file and
looks for that type in the results. It reports the success rate for each folder
and shows what moria reported for missed examples. File types without a
recognition rule are listed but not scored.

Usage: tests/accuracy.py [corpus_samples_dir]
The command fails if any scored group falls below 90 percent.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "build", "moria")
SIGS = os.path.join(HERE, "..", "signatures")

# category directory -> set of acceptable finding types
EXPECT = {
    "fs-squashfs": {"squashfs"},
    "fs-jffs2": {"jffs2"},
    "fs-ubi": {"ubi", "ubifs"},
    "fs-erofs": {"erofs"},
    "fs-ext": {"ext"},
    "fs-romfs": {"romfs"},
    "uimage": {"uimage"},
    "android-boot": {"android_boot"},
    "android-sparse": {"android_sparse"},
    "dtb": {"dtb", "fit"},  # This collection mixes plain DTBs and U-Boot FITs.
    "mcu-elf": {"elf"},
    "mcu-hex": {"ihex"},
    "fs-yaffs": {"yaffs2"},
    "bootloader-rpi": {"rpi_eeprom"},
}
# Types in the collection that do not have recognition rules yet.
NOSIG = set()
# scored as "contains at least one notable finding" rather than a fixed type
NOTABLE_ONLY = {"full-flash"}

MAX_BYTES = 6 * 1024**3
TIMEOUT = 180


def scan(path):
    try:
        r = subprocess.run([BIN, "-j", "--sigs", SIGS, path], capture_output=True,
                           timeout=TIMEOUT)
        return json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, ValueError):
        return None


def primary(findings):
    if not findings:
        return "unknown"
    best = max(findings, key=lambda f: (f["confidence"], -f["offset"]))
    return best["type"]


TIERS = {25: "magic", 60: "structural", 85: "consistent", 99: "verified"}


def tier_of(conf):
    best = "magic"
    for score, name in sorted(TIERS.items()):
        if conf >= score:
            best = name
    return best


def main():
    samples = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MORIA_CORPUS", "corpus")
    min_rate = 0.90
    worst = 1.0
    rows = []
    # calibration: for correct detections, the tier of the matching finding, and
    # whether that finding is also the highest-confidence one (primary == expected).
    tier_hits = {"magic": 0, "structural": 0, "consistent": 0, "verified": 0}
    primary_ok = 0
    primary_wrong = 0
    primary_wrong_examples = []

    for cat in sorted(os.listdir(samples)):
        d = os.path.join(samples, cat)
        if not os.path.isdir(d):
            continue
        files = [os.path.join(d, f) for f in sorted(os.listdir(d))
                 if os.path.isfile(os.path.join(d, f))]
        if not files:
            continue

        if cat in NOSIG:
            rows.append((cat, len(files), None, "no signature yet", []))
            continue

        expect = EXPECT.get(cat)
        notable_only = cat in NOTABLE_ONLY
        if expect is None and not notable_only:
            rows.append((cat, len(files), None, "not scored", []))
            continue

        hit = 0
        misses = []
        for path in files:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            d_json = scan(path)
            if d_json is None:
                misses.append((os.path.basename(path), "SCAN-ERROR"))
                continue
            types = {f["type"] for f in d_json["findings"]}
            notable = bool(d_json["findings"]) if notable_only else False
            ok = notable if notable_only else bool(expect & types)
            if ok:
                hit += 1
                if not notable_only:
                    matched = [f for f in d_json["findings"] if f["type"] in expect]
                    top = max(f["confidence"] for f in matched)
                    tier_hits[tier_of(top)] += 1
                    if primary(d_json["findings"]) in expect:
                        primary_ok += 1
                    else:
                        primary_wrong += 1
                        if len(primary_wrong_examples) < 5:
                            primary_wrong_examples.append(
                                (os.path.basename(path), primary(d_json["findings"])))
            else:
                misses.append((os.path.basename(path), primary(d_json["findings"])))
        rate = hit / len(files) if files else 0.0
        label = "notable" if notable_only else "/".join(sorted(expect))
        rows.append((cat, len(files), rate, label, misses))
        # Gate only on categories large enough to be a signal; tiny ones (e.g.
        # the single fs-romfs file, which is itself a mislabeled uImage) are
        # reported but do not fail the build.
        if expect is not None and len(files) >= 3:
            worst = min(worst, rate)

    # Report
    print(f"{'category':<16}{'files':>6}{'detected':>10}  expected / note")
    print("-" * 62)
    for cat, n, rate, label, misses in rows:
        if rate is None:
            print(f"{cat:<16}{n:>6}{'--':>10}  {label}")
        else:
            print(f"{cat:<16}{n:>6}{rate*100:>9.1f}%  {label}")
            for name, got in misses[:5]:
                print(f"{'':18}miss: {name}  -> {got}")
            if len(misses) > 5:
                print(f"{'':18}... and {len(misses)-5} more misses")
    print("-" * 62)
    # Calibration report: tier distribution of correct detections + ranking check.
    total_hits = sum(tier_hits.values())
    print("confidence calibration (correct detections by tier):")
    for name in ("verified", "consistent", "structural", "magic"):
        c = tier_hits[name]
        pct = (100.0 * c / total_hits) if total_hits else 0.0
        print(f"  {name:<11}{c:>5}  {pct:>5.1f}%")
    ranked = primary_ok + primary_wrong
    if ranked:
        print(f"expected type is the top-confidence finding: {primary_ok}/{ranked} "
              f"({100.0*primary_ok/ranked:.1f}%)")
        for name, got in primary_wrong_examples:
            print(f"    outranked: {name}  primary-> {got}")
    print("-" * 62)
    print(f"worst scored-category detection rate: {worst*100:.1f}%")
    if worst < min_rate:
        print(f"FAIL: below {min_rate*100:.0f}%")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

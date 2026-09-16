#!/usr/bin/env python3
"""ESP-IDF partition table identification regression (issue #18).

Synthetic, always-on: hand-built tables at the default 0x8000 and at a custom
offset, happy path + members, and the false-positive/hostile guards (corrupt
magic, overlapping entries, single entry, huge sizes, unaligned placement,
truncation at every boundary). Determinism: -j twice must be byte-identical.
Self-contained; no external tools. Exit nonzero on any failure.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")

ENTRIES = [
    (0x01, 0x02, 0x9000, 0x6000, "nvs"),
    (0x01, 0x01, 0xF000, 0x1000, "phy_init"),
    (0x00, 0x00, 0x10000, 0x100000, "factory"),
    (0x00, 0x10, 0x110000, 0x100000, "ota_0"),
    (0x01, 0x82, 0x210000, 0x40000, "storage"),
]


def table_bytes(entries=ENTRIES, md5=True):
    raw = bytearray()
    for ptype, subtype, off, size, label in entries:
        e = bytearray(32)
        e[0:2] = b"\xaa\x50"
        e[2], e[3] = ptype, subtype
        struct.pack_into("<I", e, 4, off)
        struct.pack_into("<I", e, 8, size)
        e[12:12 + len(label)] = label.encode()
        raw += e
    if md5:
        raw += b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(bytes(raw)).digest()
    return bytes(raw)


def flash_image(table_at=0x8000, size=0x220000, **kw):
    img = bytearray(b"\xff" * size)
    t = table_bytes(**kw)
    img[table_at:table_at + len(t)] = t
    return bytes(img)


def moria_json(data):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=120)
    assert r.returncode == 0, f"moria crashed: rc={r.returncode}"
    return json.loads(r.stdout)


def findings_of(data, t="esp32_partition_table"):
    return [f for f in moria_json(data)["findings"] if f["type"] == t]


def main():
    fails = []

    def check(cond, msg):
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            fails.append(msg)

    # --- happy path at the default offset ------------------------------------
    f = findings_of(flash_image())
    check(len(f) == 1, "default: one table finding @0x8000")
    if f:
        t = f[0]
        check(t["offset"] == 0x8000, "default: offset 0x8000")
        check(t["confidence_tier"] == "consistent", "default: consistent tier")
        check(t["size"] == (len(ENTRIES) + 1) * 32, "default: size through MD5 entry")
        mem = {m["name"]: m for m in t.get("members", [])}
        check(set(mem) == {"nvs", "phy_init", "factory", "ota_0", "storage"},
              f"default: member labels {sorted(mem)}")
        check(mem.get("nvs", {}).get("note") == "data/nvs", "default: nvs note decoded")
        check(mem.get("ota_0", {}).get("note") == "app/ota_0", "default: ota_0 note decoded")
        check(mem.get("storage", {}).get("note") == "data/spiffs",
              "default: spiffs note decoded")
        check(mem.get("nvs", {}).get("offset") == 0x9000
              and mem.get("nvs", {}).get("size") == 0x6000, "default: nvs region")
        check(mem.get("storage", {}).get("offset") == 0x210000,
              "default: storage region offset")

    # --- custom (non-default) table offset: fallback scan --------------------
    f = findings_of(flash_image(table_at=0x10000))
    check(len(f) == 1 and f[0]["offset"] == 0x10000, "custom offset: table found @0x10000")

    # --- erased terminator (no MD5 entry) ------------------------------------
    f = findings_of(flash_image(md5=False))
    check(len(f) == 1 and "no MD5 terminator" in f[0]["evidence"],
          "erased terminator: still identified")

    # --- hostile: corrupted entry magic --------------------------------------
    bad = bytearray(table_bytes())
    bad[32] = 0xFF  # second entry's first magic byte
    img = bytearray(b"\xff" * 0x220000)
    img[0x8000:0x8000 + len(bad)] = bad
    check(not findings_of(bytes(img)), "corrupt entry magic: no finding")

    # --- hostile: overlapping partitions -------------------------------------
    overlap = list(ENTRIES)
    overlap[1] = (0x01, 0x01, 0x9000, 0x1000, "phy_init")  # same start as nvs
    check(not findings_of(flash_image(entries=overlap)),
          "overlapping entries: no finding")

    # --- hostile: a single partition is not a table --------------------------
    check(not findings_of(flash_image(entries=ENTRIES[:1])),
          "single entry: no finding")

    # --- hostile: huge claimed size / offset ---------------------------------
    huge = list(ENTRIES)
    huge[2] = (0x00, 0x00, 0x10000, 0xFFFFFF00, "factory")
    check(not findings_of(flash_image(entries=huge)), "huge size: no finding")
    far = list(ENTRIES)
    far[2] = (0x00, 0x00, 0x8000000, 0x100000, "factory")  # 128 MiB offset
    check(not findings_of(flash_image(entries=far)), "huge offset: no finding")

    # --- hostile: unaligned partition offset / unaligned table ---------------
    unal = list(ENTRIES)
    unal[1] = (0x01, 0x01, 0xF004, 0x1000, "phy_init")
    check(not findings_of(flash_image(entries=unal)),
          "unaligned partition offset: no finding")
    check(not findings_of(flash_image(table_at=0x8100)),
          "unaligned table: no finding")

    # --- truncation at every boundary ----------------------------------------
    full = flash_image()
    crash = None
    for n in list(range(0x7FFE, 0x8120)) + [0x8000 + 32 * k for k in range(3, 9)]:
        try:
            moria_json(full[:n])
        except AssertionError as e:
            crash = f"truncate@0x{n:x}: {e}"
            break
    check(crash is None, crash or "truncation sweep: never crashes")

    # --- determinism ----------------------------------------------------------
    with tempfile.NamedTemporaryFile(suffix=".bin") as tf:
        tf.write(full)
        tf.flush()
        j1 = subprocess.run([MORIA, "-j", tf.name], capture_output=True).stdout
        j2 = subprocess.run([MORIA, "-j", tf.name], capture_output=True).stdout
    check(j1 == j2, "determinism: -j twice byte-identical")

    print("-" * 60)
    if fails:
        print(f"FAIL: {len(fails)} check(s) failed")
        return 1
    print("PASS: esp32 partition table identify + region map")
    return 0


if __name__ == "__main__":
    sys.exit(main())

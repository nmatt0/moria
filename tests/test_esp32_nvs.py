#!/usr/bin/env python3
"""ESP-IDF NVS identify + extract regression (issue #18).

Synthetic, always-on: hand-built page logs using the gen_samples NVS helpers.
Covers the happy path (every standard type, multi-entry string/blob), v2
blob_index/blob_data chains spanning pages, erased-page gaps, and the hostile
guards (garbage bitmap, corrupt page CRC, huge claimed sizes, truncation at
every boundary). Determinism: -j twice must be byte-identical.
Self-contained; no external tools. Exit nonzero on any failure.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")
sys.path.insert(0, HERE)
import gen_samples as gs  # noqa: E402


def happy_partition():
    """All standard types in one page, plus a long string and a v1 blob."""
    f32 = gs.nvs_entry(1, 0x24, "f32", struct.pack("<f", 1.5).ljust(8, b"\xff"))
    f64 = gs.nvs_entry(1, 0x28, "f64", struct.pack("<d", 1024.0).ljust(8, b"\xff"))
    entries = [
        gs.nvs_namespace(1, "app"),
        gs.nvs_int(1, 0x01, "u8", 255),
        gs.nvs_int(1, 0x11, "i8", -128),
        gs.nvs_int(1, 0x02, "u16", 65535),
        gs.nvs_int(1, 0x12, "i16", -32768),
        gs.nvs_int(1, 0x04, "u32", 4294967295),
        gs.nvs_int(1, 0x14, "i32", -2147483648),
        gs.nvs_int(1, 0x08, "u64", 18446744073709551615),
        gs.nvs_int(1, 0x18, "i64", -9223372036854775808),
        f32, f64,
        *gs.nvs_varlen(1, 0x21, "greeting", b"hello world\x00"),
        *gs.nvs_varlen(1, 0x21, "longstr", b"A" * 200 + b"\x00"),
        *gs.nvs_varlen(1, 0x41, "blob1", bytes(range(100))),
        *gs.nvs_varlen(1, 0x21, "password", b"hunter2\x00"),
    ]
    return gs.nvs_page(1, entries)


HAPPY_EXPECT = {
    "app:u8": ("255", "uint8_t"),
    "app:i8": ("-128", "int8_t"),
    "app:u16": ("65535", "uint16_t"),
    "app:i16": ("-32768", "int16_t"),
    "app:u32": ("4294967295", "uint32_t"),
    "app:i32": ("-2147483648", "int32_t"),
    "app:u64": ("18446744073709551615", "uint64_t"),
    "app:i64": ("-9223372036854775808", "int64_t"),
    "app:f32": ("1.5", "float"),
    "app:f64": ("1024.0", "double"),
    "app:greeting": ("hello world", "string"),
    "app:longstr": ("A" * 200, "string"),
    "app:blob1": (repr(bytes(range(100))), "blob"),
    "app:password": ("hunter2", "string"),
}


def chained_partition():
    """A v2 blob split across two pages: blob_index + chunk 0x80 on page 0,
    chunk 0x81 on page 1."""
    part1 = bytes(range(64))
    part2 = bytes(range(64, 128))
    page0 = gs.nvs_page(1, [
        gs.nvs_namespace(1, "app"),
        gs.nvs_blob_index(1, "fw", len(part1) + len(part2), 2, 0x80),
        *gs.nvs_varlen(1, 0x42, "fw", part1, chunk=0x80),
    ])
    page1 = gs.nvs_page(2, [
        *gs.nvs_varlen(1, 0x42, "fw", part2, chunk=0x81),
    ])
    return page0 + page1


def gapped_partition():
    """Valid page, erased page, valid page: the run bridges the erased gap."""
    page0 = gs.nvs_page(1, [gs.nvs_namespace(1, "app"), gs.nvs_int(1, 0x01, "a", 1)])
    page2 = gs.nvs_page(3, [gs.nvs_int(1, 0x01, "b", 2)])
    return page0 + b"\xff" * 4096 + page2


def moria_json(data):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-j", f.name], capture_output=True, timeout=120)
    assert r.returncode == 0, f"moria crashed: rc={r.returncode}"
    return json.loads(r.stdout)


def findings_of(data):
    return [f for f in moria_json(data)["findings"] if f["type"] == "esp32_nvs"]


def extract_values(data):
    """Run moria -e; return (header lines, {ns:key: (value, type)}) or None."""
    with tempfile.NamedTemporaryFile(suffix=".bin") as f, tempfile.TemporaryDirectory() as td:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA, "-e", "-C", td, f.name], capture_output=True, timeout=120)
        assert r.returncode == 0, f"moria -e crashed: rc={r.returncode}"
        for root, _dirs, files in os.walk(td):
            if "nvs-values.txt" in files:
                with open(os.path.join(root, "nvs-values.txt")) as fh:
                    lines = fh.read().splitlines()
                values = {}
                for ln in lines:
                    if ln.startswith("#") or " = " not in ln:
                        continue
                    left, _, ty = ln.rpartition(" ; ")
                    k, _, v = left.partition(" = ")
                    values[k] = (v, ty)
                return [ln for ln in lines if ln.startswith("#")], values
    return None


def main():
    fails = []

    def check(cond, msg):
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            fails.append(msg)

    # --- happy path: identify -------------------------------------------------
    happy = happy_partition()
    f = findings_of(happy)
    check(len(f) == 1, "happy: one NVS finding @0")
    if f:
        check(f[0]["confidence_tier"] == "verified", "happy: verified (page CRC)")
        check(f[0]["offset"] == 0 and f[0]["size"] == 4096, "happy: offset+size")
        codes = [d["code"] for d in f[0].get("diagnostics", [])]
        check("esp32-nvs-sensitive-key" in codes, "happy: sensitive key flagged")

    # --- happy path: extract round-trips every type ---------------------------
    got = extract_values(happy)
    check(got is not None, "happy: nvs-values.txt produced")
    if got:
        header, values = got
        missing = {k: v for k, v in HAPPY_EXPECT.items() if values.get(k) != v}
        check(not missing, f"happy: all values round-trip (mismatches: {missing or '{}'})")
        check(any("sensitive keys:" in h and "app:password" in h for h in header),
              "happy: sensitive key listed in header")

    # --- chained v2 blob spanning pages ---------------------------------------
    chained = chained_partition()
    f = findings_of(chained)
    check(len(f) == 1 and f[0]["size"] == 2 * 4096, "chain: finding spans both pages")
    got = extract_values(chained)
    expect = repr(bytes(range(128)))
    check(got is not None and got[1].get("app:fw") == (expect, "blob"),
          "chain: cross-page blob reassembled" if got else "chain: no extraction")

    # --- erased page gap -------------------------------------------------------
    f = findings_of(gapped_partition())
    check(len(f) == 1 and f[0]["size"] == 3 * 4096, "gap: extent bridges erased page")
    got = extract_values(gapped_partition())
    check(got is not None and got[1].get("app:a") == ("1", "uint8_t")
          and got[1].get("app:b") == ("2", "uint8_t"), "gap: keys from both pages")

    # --- hostile: garbage bitmap (all 'written') -------------------------------
    garbage = bytearray(happy)
    for i in range(32, 64):
        garbage[i] = 0xAA
    check(not findings_of(bytes(garbage)), "garbage bitmap: no finding, no crash")

    # --- hostile: corrupt page header CRC --------------------------------------
    corrupt = bytearray(happy)
    corrupt[28] ^= 0xFF
    check(not findings_of(bytes(corrupt)), "corrupt page CRC: no finding")

    # --- hostile: huge claimed blob size ---------------------------------------
    huge = bytearray(happy)
    # blob1 header entry: find it and blow up its dataSize (span stays small).
    # entries area starts at 64; locate the blob1 header by its key.
    idx = happy.find(b"blob1\x00")
    check(idx > 0, "huge: fixture key located")
    if idx > 0:
        eoff = idx - 8  # key field starts at entry+8
        struct.pack_into("<H", huge, eoff + 24, 0xFFFF)  # dataSize way past span
        struct.pack_into("<I", huge, eoff + 4, 0)        # crc now wrong anyway
        moria_json(bytes(huge))  # must not crash or allocate
        check(True, "huge blob dataSize: no crash")

    # --- hostile: truncation at every boundary ---------------------------------
    full = chained_partition()
    crash = None
    for n in list(range(0, 160)) + list(range(160, len(full), 32)):
        try:
            moria_json(full[:n])
        except AssertionError as e:
            crash = f"truncate@0x{n:x}: {e}"
            break
    check(crash is None, crash or "truncation sweep: never crashes")

    # --- determinism -----------------------------------------------------------
    with tempfile.NamedTemporaryFile(suffix=".bin") as tf:
        tf.write(happy)
        tf.flush()
        j1 = subprocess.run([MORIA, "-j", tf.name], capture_output=True).stdout
        j2 = subprocess.run([MORIA, "-j", tf.name], capture_output=True).stdout
    check(j1 == j2, "determinism: -j twice byte-identical")

    print("-" * 60)
    if fails:
        print(f"FAIL: {len(fails)} check(s) failed")
        return 1
    print("PASS: esp32 NVS identify + extract")
    return 0


if __name__ == "__main__":
    sys.exit(main())

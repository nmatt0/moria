#!/usr/bin/env python3
"""Regression for the -E per-section entropy column (findings + members).

-E adds a Shannon-entropy value to every finding and every located member, shown
as an ENTROPY column in the human OFFSET table and an `entropy` field in JSON.
Without -E there is neither. Fully self-contained (synthetic ext superblocks +
the gpt fixture). Run: python3 tests/test_entropy.py
"""
import json
import os
import random
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MORIA = os.path.join(HERE, "..", "build", "moria")
sys.path.insert(0, HERE)
import gen_samples  # noqa: E402


def ext_over(buf):
    """Plant a valid 64 KiB ext superblock at offset 0 of `buf` (finding size =
    64 KiB, so entropy is dominated by the buffer's contents)."""
    b = bytearray(buf)
    sb = 1024
    struct.pack_into("<I", b, sb + 0, 1000)   # s_inodes_count
    struct.pack_into("<I", b, sb + 4, 64)     # s_blocks_count_lo -> 64 * 1024 = 64 KiB
    struct.pack_into("<I", b, sb + 20, 0)     # s_first_data_block
    struct.pack_into("<I", b, sb + 24, 0)     # s_log_block_size -> 1024
    struct.pack_into("<H", b, 0x438, 0xEF53)  # magic
    return bytes(b)


def high_entropy_ext():
    rnd = random.Random(0xE47)
    return ext_over(bytes(rnd.getrandbits(8) for _ in range(64 * 1024)))


def low_entropy_ext():
    return ext_over(bytes(64 * 1024))


def run(data, args):
    with tempfile.NamedTemporaryFile(suffix=".img") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([MORIA] + args + [f.name], capture_output=True, text=True, timeout=60,
                           env={**os.environ, "NO_COLOR": "1"})
    return r.stdout


def findings(data, entropy):
    doc = json.loads(run(data, ["-j"] + (["-E"] if entropy else [])))
    return doc["findings"]


def main():
    if not os.path.exists(MORIA):
        print("moria not built", file=sys.stderr)
        return 1
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # --- JSON: entropy field is present only under -E, and reflects the data ----
    hi = findings(high_entropy_ext(), entropy=True)
    lo = findings(low_entropy_ext(), entropy=True)
    hie = [x for x in hi if x["type"] == "ext"]
    loe = [x for x in lo if x["type"] == "ext"]
    check(hie and hie[0].get("entropy", 0) > 7.5, "high-entropy ext: entropy > 7.5 under -E")
    check(loe and loe[0].get("entropy", 9) < 1.0, "low-entropy ext: entropy < 1.0 under -E")

    no_e = findings(high_entropy_ext(), entropy=False)
    check(all("entropy" not in x for x in no_e), "no -E: findings carry no entropy field")

    # --- members get entropy too (the gpt fixture has partition members) --------
    g = [x for x in findings(gen_samples.gpt_disk(), entropy=True) if x["type"] == "gpt"]
    check(g and all("entropy" in m for m in g[0].get("members", [])),
          "gpt members carry entropy under -E")
    g0 = [x for x in findings(gen_samples.gpt_disk(), entropy=False) if x["type"] == "gpt"]
    check(g0 and all("entropy" not in m for m in g0[0].get("members", [])),
          "no -E: gpt members carry no entropy")

    # --- human: ENTROPY column present only under -E ----------------------------
    human_e = run(high_entropy_ext(), ["-E"])
    human_0 = run(high_entropy_ext(), [])
    hdr_e = next((ln for ln in human_e.splitlines() if ln.startswith("OFFSET")), "")
    hdr_0 = next((ln for ln in human_0.splitlines() if ln.startswith("OFFSET")), "")
    check("ENTROPY" in hdr_e, "human -E: ENTROPY column in the header")
    check("ENTROPY" not in hdr_0, "human without -E: no ENTROPY column")
    # the high-entropy value shows in the table
    check(any("8.00" in ln for ln in human_e.splitlines()),
          "human -E: the 8.00 entropy value is rendered")

    print("-" * 60)
    if fails:
        for m in fails:
            print("FAIL:", m)
        return 1
    print("PASS: -E entropy column on findings + members (human + JSON), off by default")
    return 0


if __name__ == "__main__":
    sys.exit(main())

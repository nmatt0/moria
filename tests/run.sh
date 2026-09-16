#!/usr/bin/env bash
# One-shot test runner: build, synthetic regression (hard gate), corpus accuracy
# (informational; needs a local firmware corpus), and a short fuzz smoke (needs clang).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/4] build (Release, -Wall -Wextra)"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build -j >/dev/null
echo "  ok"

echo "[2/4] unit tests + synthetic sample regression (hard gate)"
./build/moria_unit
python3 tests/test_samples.py
# Extraction round-trip (hard gate when mksquashfs is present; self-skips if not).
python3 tests/test_extract.py
# Human -e extraction-tree rendering (self-contained hard gate; stdlib fixtures).
python3 tests/test_human_tree.py
# GPT/MBR partition-table identify + region map (synthetic + real-tool round-trip).
python3 tests/test_partition.py
# Legacy block filesystems: NILFS2/Minix/ReiserFS/UFS/APFS/LogFS identify (+ real mkfs.minix).
python3 tests/test_legacy_fs.py
# RFP section extraction + LZARI decode round-trip (self-contained hard gate).
python3 tests/test_rae_rfp.py
# VBF block extraction + LZSS decode round-trip (self-contained hard gate).
python3 tests/test_vbf.py
echo
python3 tests/test_uboot_env.py
echo
python3 tests/test_vbmeta.py
echo
python3 tests/test_fit_signing.py
# UPX PackHeader detection + tampered-header heuristic (self-contained; also
# cross-checks the real `upx` tool when installed).
python3 tests/test_upx.py
# UPX unpacking: moria -e must reproduce `upx -d` byte-for-byte (self-skips
# without the `upx` tool; adds cross-arch packs when a toolchain is present).
python3 tests/test_upx_extract.py

echo "[3/4] the corpus accuracy (informational)"
if [ -d "${MORIA_CORPUS:-corpus}" ]; then
  python3 tests/accuracy.py || echo "  (accuracy gate reported failures — review above)"
else
  echo "  (a local firmware corpus not present, skipped)"
fi

echo "[4/4] fuzz smoke, 15s (informational)"
if command -v clang++ >/dev/null 2>&1; then
  fuzz/build.sh >/dev/null 2>&1
  # libFuzzer WRITES new inputs into its corpus dir, so seed a throwaway
  # fuzz/corpus (gitignored) from the fixtures — never point it at tests/samples.
  mkdir -p fuzz/corpus && cp -n tests/samples/* fuzz/corpus/ 2>/dev/null || true
  if ./fuzz_scan -max_total_time=15 -rss_limit_mb=4096 fuzz/corpus >/dev/null 2>&1; then
    echo "  fuzz OK (no crashes)"
  else
    echo "  FUZZ CRASH — investigate"; exit 1
  fi
  rm -f fuzz_scan
else
  echo "  (clang++ not present, skipped)"
fi

echo "ALL DONE"

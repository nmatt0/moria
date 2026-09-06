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

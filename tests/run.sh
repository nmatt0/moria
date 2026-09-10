#!/usr/bin/env bash
# Run the build, required checks with made-up files, an optional accuracy check
# with a local firmware collection, and a short random-input check using clang.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/4] build (Release, -Wall -Wextra)"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build -j >/dev/null
echo "  ok"

echo "[2/4] required checks with made-up sample files"
./build/moria_unit
python3 tests/test_samples.py
# Check unpacking when mksquashfs is available; otherwise this check skips itself.
python3 tests/test_extract.py
# Check that RFP sections and LZARI data unpack to the original bytes.
python3 tests/test_rae_rfp.py

echo "[3/4] optional accuracy check using a local firmware collection"
if [ -d "${MORIA_CORPUS:-corpus}" ]; then
  python3 tests/accuracy.py || echo "  (accuracy gate reported failures — review above)"
else
  echo "  (local firmware collection not present; skipped)"
fi

echo "[4/4] optional 15-second random-input check"
if command -v clang++ >/dev/null 2>&1; then
  fuzz/build.sh >/dev/null 2>&1
  # libFuzzer writes new inputs while it runs. Copy the examples into the
  # ignored fuzz/corpus working folder; never write into tests/samples.
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

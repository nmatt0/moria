#!/usr/bin/env bash
# Build the libFuzzer target (clang + libFuzzer + ASan). Run from the repo root.
#   fuzz/build.sh && ./fuzz_scan -max_total_time=60 fuzz/corpus
set -euo pipefail
cd "$(dirname "$0")/.."
clang++ -std=c++20 -O1 -g -fsanitize=fuzzer,address -I src -I third_party \
  -DFT_FUZZ_SIGDIR="\"$PWD/signatures\"" \
  src/scan.cpp src/ahocorasick.cpp src/resolve.cpp src/expr.cpp \
  src/layout.cpp src/sigload.cpp src/secrets.cpp src/archives.cpp src/validators/*.cpp \
  fuzz/fuzz_scan.cpp -o fuzz_scan
echo "built ./fuzz_scan"

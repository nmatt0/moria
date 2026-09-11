#!/usr/bin/env bash
# Build the libFuzzer target (clang + libFuzzer + ASan). Run from the repo root.
#   fuzz/build.sh && ./fuzz_scan -max_total_time=60 fuzz/corpus
set -euo pipefail
cd "$(dirname "$0")/.."
# Compile the whole src tree except main.cpp (libFuzzer supplies its own main),
# so the fuzz build never drifts out of sync with newly added modules. Signatures
# are loaded from disk via FT_FUZZ_SIGDIR, so the generated embedded set (built
# only under CMake) is not needed here.
mapfile -t SRCS < <(find src -name '*.cpp' ! -name 'main.cpp' | sort)
clang++ -std=c++20 -O1 -g -fsanitize=fuzzer,address -I src -I third_party \
  -DFT_FUZZ_SIGDIR="\"$PWD/signatures\"" \
  "${SRCS[@]}" fuzz/fuzz_scan.cpp -o fuzz_scan
echo "built ./fuzz_scan"

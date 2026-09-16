#!/usr/bin/env bash
# Build the libFuzzer targets (clang + libFuzzer + ASan). Run from the repo root.
#   fuzz/build.sh && ./fuzz_scan -max_total_time=60 fuzz/corpus
set -euo pipefail
cd "$(dirname "$0")/.."
# Compile the whole src tree except main.cpp (libFuzzer supplies its own main),
# so the fuzz build never drifts out of sync with newly added modules. Signatures
# are loaded from disk via FT_FUZZ_SIGDIR, so the generated embedded set (built
# only under CMake) is not needed here.
mapfile -t SRCS < <(find src -name '*.cpp' ! -name 'main.cpp' | sort)
# Xcode clang lacks the libFuzzer runtime; override with a clang that has it
# (e.g. CXX=/opt/homebrew/opt/llvm/bin/clang++ on macOS).
CXX="${CXX:-clang++}"
for target in fuzz_scan fuzz_esp32_part fuzz_esp32_nvs; do
  "$CXX" -std=c++20 -O1 -g -fsanitize=fuzzer,address -I src -I third_party \
    -DFT_FUZZ_SIGDIR="\"$PWD/signatures\"" \
    "${SRCS[@]}" "fuzz/${target}.cpp" -o "$target"
  echo "built ./$target"
done

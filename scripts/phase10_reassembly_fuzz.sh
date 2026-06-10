#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${VECTORNET_FUZZ_BUILD_DIR:-"$root_dir/build-fuzz-llvm"}
fuzz_cxx=${VECTORNET_FUZZ_CXX:-/opt/homebrew/opt/llvm/bin/clang++}
run_corpus=$(mktemp -d "${TMPDIR:-/tmp}/vectornet-phase10.XXXXXX")
trap 'rm -rf "$run_corpus"' EXIT INT TERM
cp "$root_dir"/test/fuzz/corpus/reassembly/* "$run_corpus"/

if [ ! -x "$fuzz_cxx" ]; then
    echo "phase10: libFuzzer compiler not found: $fuzz_cxx" >&2
    echo "phase10: install Homebrew llvm or set VECTORNET_FUZZ_CXX" >&2
    exit 1
fi

"$fuzz_cxx" --version

cmake -S "$root_dir" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_CXX_COMPILER="$fuzz_cxx" \
    -DBUILD_TESTING=OFF \
    -DVECTORNET_BUILD_FUZZERS=ON
cmake --build "$build_dir" --target vectornet_reassembly_fuzzer -j
"$build_dir/vectornet_reassembly_fuzzer" \
    "$run_corpus" \
    -seed=7912018 \
    -runs=5000 \
    -max_len=4096 \
    -print_final_stats=1

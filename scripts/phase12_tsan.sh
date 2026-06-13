#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${VECTORNET_TSAN_BUILD_DIR:-"$root_dir/build-tsan"}

cmake -S "$root_dir" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DBUILD_TESTING=ON \
    -DVECTORNET_ENABLE_TSAN=ON
cmake --build "$build_dir" --target vectornet_spsc_stress -j
TSAN_OPTIONS="halt_on_error=1:history_size=7" \
    "$build_dir/vectornet_spsc_stress"

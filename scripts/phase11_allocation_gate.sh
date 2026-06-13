#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${VECTORNET_BUILD_DIR:-"$root_dir/build"}
interposer="$build_dir/libvectornet_alloc_interposer.dylib"
benchmark="$build_dir/vectornet_packet_pool_bench"

cmake -S "$root_dir" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_OSX_ARCHITECTURES=arm64
cmake --build "$build_dir" \
    --target vectornet_alloc_interposer vectornet_packet_pool_bench -j

if [ ! -f "$interposer" ]; then
    echo "phase11: interposer library missing: $interposer" >&2
    exit 1
fi

DYLD_INSERT_LIBRARIES="$interposer" "$benchmark"

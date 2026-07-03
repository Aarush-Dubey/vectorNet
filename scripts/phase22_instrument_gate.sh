#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${VECTORNET_BUILD_DIR:-"$root_dir/build"}
run_id=$(date -u '+%Y%m%dT%H%M%SZ')
artifact_dir="$root_dir/.vectornet-artifacts/phase22/instrument-$run_id"
mkdir -p "$artifact_dir"

cmake -S "$root_dir" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_OSX_ARCHITECTURES=arm64
cmake --build "$build_dir" --target vectornet_instrument_probe -j
"$build_dir/vectornet_instrument_probe" \
    "$artifact_dir/histogram.csv" \
    "$artifact_dir/histogram.jsonl"
echo "artifact=$artifact_dir"

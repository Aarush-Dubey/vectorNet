#!/bin/sh
set -u

fail() {
    printf '%s\n' "phase24 counter/proxy failed: $*" >&2
    exit 1
}

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${VECTORNET_BUILD_DIR:-"$root_dir/build"}
artifact_root=${VECTORNET_ARTIFACT_ROOT:-"$root_dir/.vectornet-artifacts/phase24"}
evidence_root=${VECTORNET_EVIDENCE_ROOT:-"$root_dir/bench/evidence/phase24"}
trials=${VECTORNET_PROXY_TRIALS:-5}
run_id=$(date -u +%Y%m%dT%H%M%SZ)
artifact_dir="$artifact_root/counter-proxy-$run_id"
mkdir -p "$artifact_dir" "$evidence_root"

cmake -S "$root_dir" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_OSX_ARCHITECTURES=arm64 || fail "configure current"
cmake --build "$build_dir" \
    --target vectornet_alloc_interposer vectornet_packet_pool_bench -j ||
    fail "build current proxy"

xctrace list templates >"$artifact_dir/xctrace_templates.txt" 2>&1 || true
xcodebuild -version >"$artifact_dir/xcode_version.txt" 2>&1 || true
xcode-select -p >"$artifact_dir/xcode_select.txt" 2>&1 || true

git -C "$root_dir" ls-tree -r --name-only phase10-pre-pool \
    >"$artifact_dir/phase10_files.txt" 2>&1 || true
git -C "$root_dir" ls-tree -r --name-only phase11-pooled \
    >"$artifact_dir/phase11_files.txt" 2>&1 || true
if grep -q '^tools/packet_pool_bench.cpp$' "$artifact_dir/phase10_files.txt"; then
    phase10_replay_present=true
else
    phase10_replay_present=false
fi
if grep -q '^tools/packet_pool_bench.cpp$' "$artifact_dir/phase11_files.txt"; then
    phase11_replay_present=true
else
    phase11_replay_present=false
fi

interposer="$build_dir/libvectornet_alloc_interposer.dylib"
benchmark="$build_dir/vectornet_packet_pool_bench"
index=1
while [ "$index" -le "$trials" ]; do
    DYLD_INSERT_LIBRARIES="$interposer" "$benchmark" \
        >"$artifact_dir/proxy_trial_$index.json" \
        2>"$artifact_dir/proxy_trial_$index.stderr" ||
        fail "proxy trial $index"
    cp "$artifact_dir/proxy_trial_$index.json" \
        "$evidence_root/proxy_trial_${index}_$run_id.json"
    index=$((index + 1))
done

trace_dir="$artifact_dir/cpu_counters.trace"
xctrace record --template 'CPU Counters' --time-limit 2s --no-prompt \
    --output "$trace_dir" \
    --target-stdout "$artifact_dir/xctrace_target_stdout.txt" \
    --env "DYLD_INSERT_LIBRARIES=$interposer" \
    --launch -- "$benchmark" \
    >"$artifact_dir/xctrace_record.stdout" \
    2>"$artifact_dir/xctrace_record.stderr"
xctrace_record_exit=$?
if [ ! -d "$trace_dir" ]; then
    fail "CPU Counters trace not created"
fi
xctrace export --input "$trace_dir" --toc \
    --output "$artifact_dir/counter_toc.xml" ||
    fail "export CPU Counters TOC"
sed -E \
    -e 's/ uuid="[^"]+"/ uuid="[redacted]"/g' \
    -e 's#path="/[^"]+"#path="[redacted]"#g' \
    -e 's#value="/[^"]+"#value="[redacted]"#g' \
    "$artifact_dir/counter_toc.xml" \
    >"$artifact_dir/counter_toc_sanitized.xml"
grep -E 'schema=|countingModes|metricLegend|l1d_miss_sampling|HITM|cache-to-cache|Cache-to-Cache|snoop' \
    "$artifact_dir/counter_toc_sanitized.xml" \
    >"$artifact_dir/counter_schema_evidence.txt" || true

if grep -Eiq 'HITM|cache-to-cache|Cache-to-Cache|snoop' \
    "$artifact_dir/counter_toc_sanitized.xml"; then
    hitm_supported=true
else
    hitm_supported=false
fi
if grep -q 'l1d_miss_sampling' "$artifact_dir/counter_toc_sanitized.xml"; then
    l1d_sampling_visible=true
else
    l1d_sampling_visible=false
fi

os_version=$(sw_vers -productVersion)
os_build=$(sw_vers -buildVersion)
kernel=$(uname -r)
chip=$(sysctl -n machdep.cpu.brand_string)
commit=$(git -C "$root_dir" rev-parse HEAD)
xcode_one_line=$(tr '\n' ' ' <"$artifact_dir/xcode_version.txt" | sed 's/"/'\''/g')

cat >"$artifact_dir/summary.json" <<EOF
{"phase":24,"gate":"Apple-Silicon-counter-proxy-evidence","actual_utc":"$run_id","source_commit":"$commit","macos":"$os_version","build":"$os_build","kernel":"$kernel","chip":"$chip","xcode":"$xcode_one_line","template":"CPU Counters","xctrace_record_exit":$xctrace_record_exit,"trace_created":true,"phase10_packet_pool_replay_present":$phase10_replay_present,"phase11_packet_pool_replay_present":$phase11_replay_present,"hitm_or_cache_to_cache_counter_visible":$hitm_supported,"l1d_sampling_label_visible":$l1d_sampling_visible,"proxy_trials":$trials,"proxy_scope":"wall-clock packet-pool hot-window throughput proxy only; no cache-miss or HITM claim","status":"pass"}
EOF

cp "$artifact_dir/summary.json" "$evidence_root/summary_$run_id.json"
cp "$artifact_dir/xctrace_templates.txt" "$evidence_root/xctrace_templates_$run_id.txt"
cp "$artifact_dir/counter_toc_sanitized.xml" \
    "$evidence_root/counter_toc_sanitized_$run_id.xml"
cp "$artifact_dir/counter_schema_evidence.txt" \
    "$evidence_root/counter_schema_evidence_$run_id.txt"
cp "$artifact_dir/xctrace_record.stdout" \
    "$evidence_root/xctrace_record_$run_id.stdout"
cp "$artifact_dir/xctrace_record.stderr" \
    "$evidence_root/xctrace_record_$run_id.stderr"

cat "$artifact_dir/summary.json"
printf '\nartifact=%s\n' "$artifact_dir"
printf 'evidence=%s\n' "$evidence_root"

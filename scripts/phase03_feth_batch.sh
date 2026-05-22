#!/bin/sh
set -u

fail() {
    printf '%s\n' "phase03 feth batch failed: $*" >&2
    exit 1
}

wait_bounded() {
    process_id=$1
    attempts=0
    while kill -0 "$process_id" >/dev/null 2>&1 && [ "$attempts" -lt 55 ]; do
        attempts=$((attempts + 1))
        sleep 1
    done
    if kill -0 "$process_id" >/dev/null 2>&1; then
        sudo kill -TERM "$process_id" >/dev/null 2>&1 || true
        return 124
    fi
    wait "$process_id"
}

VECTORNET_BPF_PROBE=${VECTORNET_BPF_PROBE:-build/vectornet_link_probe}
VECTORNET_BATCH_PROBE=${VECTORNET_BATCH_PROBE:-build/vectornet_batch_probe}
ARTIFACT_ROOT=${VECTORNET_ARTIFACT_ROOT:-.vectornet-artifacts/phase03}
THROUGHPUT_FRAMES=${VECTORNET_THROUGHPUT_FRAMES:-4096}
TRACE_FRAMES=${VECTORNET_TRACE_FRAMES:-128}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TRACE_XSLT="$SCRIPT_DIR/system_trace_syscalls.xslt"

[ -x "$VECTORNET_BPF_PROBE" ] || fail "missing $VECTORNET_BPF_PROBE"
[ -x "$VECTORNET_BATCH_PROBE" ] || fail "missing $VECTORNET_BATCH_PROBE"
[ -f "$TRACE_XSLT" ] || fail "missing $TRACE_XSLT"
if ifconfig feth0 >/dev/null 2>&1 || ifconfig feth1 >/dev/null 2>&1; then
    fail "feth0 or feth1 already exists; refusing to alter it"
fi

run_id=$(date -u +%Y%m%dT%H%M%SZ)
artifact_dir="$ARTIFACT_ROOT/feth-batch-$run_id"
mkdir -p "$artifact_dir"
created0=0
created1=0

cleanup() {
    if [ "$created1" -eq 1 ]; then
        sudo ifconfig feth1 destroy >/dev/null 2>&1 || true
    fi
    if [ "$created0" -eq 1 ]; then
        sudo ifconfig feth0 destroy >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT HUP INT TERM

sudo -v || fail "sudo authorization"
sudo ifconfig feth0 create || fail "create feth0"
created0=1
sudo ifconfig feth1 create || fail "create feth1"
created1=1
sudo ifconfig feth1 peer feth0 || fail "pair feth interfaces"
sudo ifconfig feth0 up || fail "bring feth0 up"
sudo ifconfig feth1 up || fail "bring feth1 up"

destination=$(sudo "$VECTORNET_BPF_PROBE" info --interface feth1 --mac-only) ||
    fail "read feth1 metadata"

sudo "$VECTORNET_BATCH_PROBE" rx --interface feth1 --frames "$THROUGHPUT_FRAMES" \
    >"$artifact_dir/throughput-rx.json" 2>"$artifact_dir/throughput-rx.stderr" &
throughput_rx_pid=$!
sleep 1
sudo "$VECTORNET_BATCH_PROBE" tx --interface feth0 --destination "$destination" \
    --frames "$THROUGHPUT_FRAMES" \
    >"$artifact_dir/throughput-tx.json" 2>"$artifact_dir/throughput-tx.stderr"
throughput_tx_exit=$?
wait_bounded "$throughput_rx_pid"
throughput_rx_exit=$?
[ "$throughput_tx_exit" -eq 0 ] || fail "throughput TX exit $throughput_tx_exit"
[ "$throughput_rx_exit" -eq 0 ] || fail "throughput RX exit $throughput_rx_exit"

max_batch=$(sed -E 's/.*"max_frames_per_read":([0-9]+).*/\1/' \
    "$artifact_dir/throughput-rx.json")
dropped=$(sed -E 's/.*"bpf_dropped":([0-9]+).*/\1/' \
    "$artifact_dir/throughput-rx.json")
[ "$max_batch" -gt 1 ] || fail "multi-record BPF read not observed"

sudo /usr/bin/dtruss "$VECTORNET_BATCH_PROBE" \
    rx --interface feth1 --frames "$TRACE_FRAMES" \
    >"$artifact_dir/trace-rx.json" 2>"$artifact_dir/dtruss-read.log" &
trace_rx_pid=$!
sleep 2
sudo /usr/bin/dtruss "$VECTORNET_BATCH_PROBE" \
    tx --interface feth0 --destination "$destination" --frames "$TRACE_FRAMES" \
    >"$artifact_dir/trace-tx.json" 2>"$artifact_dir/dtruss-write.log"
trace_tx_exit=$?
wait_bounded "$trace_rx_pid"
trace_rx_exit=$?
[ "$trace_tx_exit" -eq 0 ] || fail "dtruss TX exit $trace_tx_exit"
[ "$trace_rx_exit" -eq 0 ] || fail "dtruss RX exit $trace_rx_exit"
if /usr/bin/grep -Eq 'failed to execute|Operation not permitted' \
    "$artifact_dir/dtruss-read.log" "$artifact_dir/dtruss-write.log"; then
    fail "dtruss unavailable"
fi
dtruss_read_rows=$(/usr/bin/grep -Ec 'read(_nocancel)?\(' \
    "$artifact_dir/dtruss-read.log" || true)
dtruss_write_rows=$(/usr/bin/grep -Ec 'write(_nocancel)?\(' \
    "$artifact_dir/dtruss-write.log" || true)
if [ "$dtruss_read_rows" -eq 0 ] || [ "$dtruss_write_rows" -eq 0 ]; then
    /usr/bin/grep -q 'system integrity protection is on' \
        "$artifact_dir/dtruss-read.log" || fail "dtruss zero rows without SIP evidence"
    dtruss_status=unsupported_under_default_sip
else
    dtruss_status=available
fi

artifact_abs=$(cd "$artifact_dir" && pwd)
batch_dir=$(cd "$(dirname "$VECTORNET_BATCH_PROBE")" && pwd)
batch_abs="$batch_dir/$(basename "$VECTORNET_BATCH_PROBE")"
system_trace="$artifact_abs/system-trace.trace"
trace_notification="com.apple.vectornet.phase03.$run_id"

/usr/bin/notifyutil -1 "$trace_notification" >"$artifact_dir/xctrace-notify.log" &
notify_pid=$!
sudo env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
    xcrun xctrace record --template 'System Trace' --output "$system_trace" \
    --time-limit 10s --notify-tracing-started "$trace_notification" \
    --target-stdout "$artifact_abs/system-trace-rx.json" \
    --launch -- "$batch_abs" rx --interface feth1 --frames "$TRACE_FRAMES" \
    >"$artifact_dir/xctrace-record.stdout" 2>"$artifact_dir/xctrace-record.stderr" &
xctrace_pid=$!
wait_bounded "$notify_pid" || fail "System Trace start notification timed out"
sleep 1
sudo "$VECTORNET_BATCH_PROBE" tx --interface feth0 --destination "$destination" \
    --frames "$TRACE_FRAMES" >"$artifact_dir/system-trace-tx.json" \
    2>"$artifact_dir/system-trace-tx.stderr"
xctrace_tx_exit=$?
wait_bounded "$xctrace_pid"
xctrace_record_exit=$?
[ "$xctrace_tx_exit" -eq 0 ] || fail "System Trace TX exit $xctrace_tx_exit"
[ "$xctrace_record_exit" -eq 0 ] || fail "System Trace record exit $xctrace_record_exit"

sudo env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
    xcrun xctrace export --input "$system_trace" --toc \
    --output "$artifact_abs/system-trace-toc.xml" \
    >"$artifact_dir/xctrace-export.stdout" 2>"$artifact_dir/xctrace-export.stderr"
xctrace_export_exit=$?
[ "$xctrace_export_exit" -eq 0 ] || fail "System Trace export exit $xctrace_export_exit"
sudo env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
    xcrun xctrace export --input "$system_trace" \
    --xpath '/trace-toc/run[@number="1"]/data/table[@schema="syscall"]' \
    --output "$artifact_abs/system-trace-rx-syscalls.xml" \
    >"$artifact_dir/xctrace-syscall-export.stdout" \
    2>"$artifact_dir/xctrace-syscall-export.stderr"
xctrace_syscall_export_exit=$?
[ "$xctrace_syscall_export_exit" -eq 0 ] ||
    fail "System Trace syscall export exit $xctrace_syscall_export_exit"
sudo chown -R "$(id -u):$(id -g)" "$artifact_dir"
/usr/bin/grep -Eqi 'syscall|system-call' "$artifact_dir/system-trace-toc.xml" ||
    fail "System Trace TOC exposes no syscall table"

read_id=$(/usr/bin/xmllint --xpath \
    'string((//syscall[@fmt="read"]/@id)[1])' \
    "$artifact_dir/system-trace-rx-syscalls.xml")
kevent_id=$(/usr/bin/xmllint --xpath \
    'string((//syscall[@fmt="kevent"]/@id)[1])' \
    "$artifact_dir/system-trace-rx-syscalls.xml")
[ -n "$read_id" ] || fail "System Trace has no read syscall"
[ -n "$kevent_id" ] || fail "System Trace has no kevent syscall"
read_rows=$(/usr/bin/xmllint --xpath \
    "count(//row[syscall[@id='$read_id' or @ref='$read_id']])" \
    "$artifact_dir/system-trace-rx-syscalls.xml")
kevent_rows=$(/usr/bin/xmllint --xpath \
    "count(//row[syscall[@id='$kevent_id' or @ref='$kevent_id']])" \
    "$artifact_dir/system-trace-rx-syscalls.xml")
rx_poll_calls=$(sed -E 's/.*"poll_calls":([0-9]+).*/\1/' \
    "$artifact_dir/system-trace-rx.json")
[ "$read_rows" -eq "$rx_poll_calls" ] ||
    fail "System Trace read count differs from poll count"
[ "$read_rows" -lt "$TRACE_FRAMES" ] || fail "read syscall was not amortized"

sudo "$VECTORNET_BATCH_PROBE" rx --interface feth1 --frames "$TRACE_FRAMES" \
    >"$artifact_dir/system-trace-tx-peer-rx.json" \
    2>"$artifact_dir/system-trace-tx-peer-rx.stderr" &
tx_peer_rx_pid=$!
sleep 1
tx_system_trace="$artifact_abs/system-trace-tx.trace"
sudo env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
    xcrun xctrace record --template 'System Trace' --output "$tx_system_trace" \
    --time-limit 10s --target-stdout "$artifact_abs/system-trace-target-tx.json" \
    --launch -- "$batch_abs" tx --interface feth0 --destination "$destination" \
    --frames "$TRACE_FRAMES" >"$artifact_dir/xctrace-tx-record.stdout" \
    2>"$artifact_dir/xctrace-tx-record.stderr"
xctrace_tx_record_exit=$?
wait_bounded "$tx_peer_rx_pid"
tx_peer_rx_exit=$?
[ "$xctrace_tx_record_exit" -eq 0 ] ||
    fail "System Trace TX record exit $xctrace_tx_record_exit"
[ "$tx_peer_rx_exit" -eq 0 ] || fail "System Trace TX peer RX exit $tx_peer_rx_exit"
sudo env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
    xcrun xctrace export --input "$tx_system_trace" \
    --xpath '/trace-toc/run[@number="1"]/data/table[@schema="syscall"]' \
    --output "$artifact_abs/system-trace-tx-syscalls.xml" \
    >"$artifact_dir/xctrace-tx-export.stdout" \
    2>"$artifact_dir/xctrace-tx-export.stderr"
xctrace_tx_export_exit=$?
[ "$xctrace_tx_export_exit" -eq 0 ] ||
    fail "System Trace TX export exit $xctrace_tx_export_exit"
sudo chown -R "$(id -u):$(id -g)" "$artifact_dir"
write_id=$(/usr/bin/xmllint --xpath \
    'string((//syscall[@fmt="write"]/@id)[1])' \
    "$artifact_dir/system-trace-tx-syscalls.xml")
[ -n "$write_id" ] || fail "System Trace has no write syscall"
write_rows=$(/usr/bin/xmllint --xpath \
    "count(//row[syscall[@id='$write_id' or @ref='$write_id']])" \
    "$artifact_dir/system-trace-tx-syscalls.xml")
[ "$write_rows" -eq "$TRACE_FRAMES" ] ||
    fail "System Trace BPF write count differs from frame count"

/usr/bin/xsltproc --stringparam mode rx "$TRACE_XSLT" \
    "$artifact_dir/system-trace-rx-syscalls.xml" \
    >"$artifact_dir/system-trace-rx.csv" || fail "sanitize RX System Trace"
/usr/bin/xsltproc --stringparam mode tx "$TRACE_XSLT" \
    "$artifact_dir/system-trace-tx-syscalls.xml" \
    >"$artifact_dir/system-trace-tx.csv" || fail "sanitize TX System Trace"
rx_csv_rows=$(($(wc -l <"$artifact_dir/system-trace-rx.csv") - 1))
tx_csv_rows=$(($(wc -l <"$artifact_dir/system-trace-tx.csv") - 1))
[ "$rx_csv_rows" -eq $((read_rows + kevent_rows)) ] ||
    fail "sanitized RX timeline count mismatch"
[ "$tx_csv_rows" -eq "$write_rows" ] ||
    fail "sanitized TX timeline count mismatch"
if /usr/bin/grep -Eqi \
    'UUID|([0-9A-F]{2}:){5}[0-9A-F]{2}|[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}' \
    "$artifact_dir/system-trace-rx.csv" "$artifact_dir/system-trace-tx.csv"; then
    fail "sanitized System Trace contains prohibited identifier"
fi

os_version=$(sw_vers -productVersion)
os_build=$(sw_vers -buildVersion)
kernel=$(uname -r)
chip=$(sysctl -n machdep.cpu.brand_string)
commit=$(DEVELOPER_DIR=/Library/Developer/CommandLineTools git rev-parse HEAD)
cat >"$artifact_dir/summary.json" <<EOF
{"phase":3,"gate":"buffered-bpf-batch","actual_utc":"$run_id","commit":"$commit","macos":"$os_version","build":"$os_build","kernel":"$kernel","chip":"$chip","topology":"feth0/feth1","tx_api":"BPF","throughput_frames":$THROUGHPUT_FRAMES,"trace_frames":$TRACE_FRAMES,"max_frames_per_read":$max_batch,"bpf_dropped":$dropped,"throughput_rx_exit":$throughput_rx_exit,"throughput_tx_exit":$throughput_tx_exit,"dtruss_rx_exit":$trace_rx_exit,"dtruss_tx_exit":$trace_tx_exit,"dtruss_read_rows":$dtruss_read_rows,"dtruss_write_rows":$dtruss_write_rows,"dtruss_status":"$dtruss_status","xctrace_record_exit":$xctrace_record_exit,"xctrace_export_exit":$xctrace_export_exit,"xctrace_syscall_export_exit":$xctrace_syscall_export_exit,"xctrace_read_rows":$read_rows,"xctrace_kevent_rows":$kevent_rows,"xctrace_tx_record_exit":$xctrace_tx_record_exit,"xctrace_tx_export_exit":$xctrace_tx_export_exit,"xctrace_write_rows":$write_rows,"sanitized_rx_rows":$rx_csv_rows,"sanitized_tx_rows":$tx_csv_rows,"status":"pass","pf":"not_applied","dummynet":"not_applied"}
EOF

cat "$artifact_dir/summary.json"
printf '\nartifact=%s\n' "$artifact_dir"

#!/bin/sh
set -u

fail() {
    printf '%s\n' "phase23 feth dummynet failed: $*" >&2
    exit 1
}

wait_bounded() {
    process_id=$1
    attempts=0
    while kill -0 "$process_id" >/dev/null 2>&1 && [ "$attempts" -lt 12 ]; do
        attempts=$((attempts + 1))
        sleep 1
    done
    if kill -0 "$process_id" >/dev/null 2>&1; then
        sudo -n kill -TERM "$process_id" >/dev/null 2>&1 || true
        return 124
    fi
    wait "$process_id"
}

VECTORNET_BENCH_RUNNER=${VECTORNET_BENCH_RUNNER:-build/vectornet_bench_runner}
ARTIFACT_ROOT=${VECTORNET_ARTIFACT_ROOT:-.vectornet-artifacts/phase23}
EVIDENCE_ROOT=${VECTORNET_EVIDENCE_ROOT:-bench/evidence/phase23}
DELAY_MS=${VECTORNET_DELAY_MS:-10}
PLR=${VECTORNET_PLR:-0.001}
WARMUP_MS=${VECTORNET_WARMUP_MS:-500}
DURATION_MS=${VECTORNET_DURATION_MS:-1500}
MAX_RUNTIME_MS=${VECTORNET_MAX_RUNTIME_MS:-6000}
PAYLOAD_BYTES=${VECTORNET_PAYLOAD_BYTES:-256}
TCP_PORT=${VECTORNET_TCP_PORT:-46000}
PIPE_A=41001
PIPE_B=41002
PF_ANCHOR=com.apple/vectornet

[ -x "$VECTORNET_BENCH_RUNNER" ] || fail "missing $VECTORNET_BENCH_RUNNER"
if ifconfig feth0 >/dev/null 2>&1 || ifconfig feth1 >/dev/null 2>&1; then
    fail "feth0 or feth1 already exists; refusing to alter it"
fi

default_iface=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')
[ "$default_iface" != "feth0" ] || fail "feth0 is default route interface"
[ "$default_iface" != "feth1" ] || fail "feth1 is default route interface"

run_id=$(date -u +%Y%m%dT%H%M%SZ)
artifact_dir="$ARTIFACT_ROOT/feth-dummynet-$run_id"
evidence_dir="$EVIDENCE_ROOT"
mkdir -p "$artifact_dir" "$evidence_dir"
rules_file="$artifact_dir/pf-anchor.rules"
created0=0
created1=0
sudo_ready=0
pf_token=
custom_server_pid=
tcp_server_pid=

cleanup() {
    if [ -n "$custom_server_pid" ] &&
        kill -0 "$custom_server_pid" >/dev/null 2>&1; then
        if [ "$sudo_ready" -eq 1 ]; then
            sudo -n kill -TERM "$custom_server_pid" >/dev/null 2>&1 || true
        fi
    fi
    if [ -n "$tcp_server_pid" ] &&
        kill -0 "$tcp_server_pid" >/dev/null 2>&1; then
        kill -TERM "$tcp_server_pid" >/dev/null 2>&1 || true
    fi
    if [ "$sudo_ready" -eq 1 ]; then
        sudo -n pfctl -a "$PF_ANCHOR" -F all >/dev/null 2>&1 || true
        if [ -n "$pf_token" ]; then
            sudo -n pfctl -X "$pf_token" >/dev/null 2>&1 || true
        fi
        sudo -n dnctl pipe delete "$PIPE_A" "$PIPE_B" >/dev/null 2>&1 || true
        if [ "$created1" -eq 1 ]; then
            sudo -n ifconfig feth1 destroy >/dev/null 2>&1 || true
        fi
        if [ "$created0" -eq 1 ]; then
            sudo -n ifconfig feth0 destroy >/dev/null 2>&1 || true
        fi
        {
            printf 'cleanup_actual_utc=%s\n' "$(date -u +%Y%m%dT%H%M%SZ)"
            if ifconfig feth0 >/dev/null 2>&1; then
                printf 'feth0_present=true\n'
            else
                printf 'feth0_present=false\n'
            fi
            if ifconfig feth1 >/dev/null 2>&1; then
                printf 'feth1_present=true\n'
            else
                printf 'feth1_present=false\n'
            fi
            printf 'dnctl_pipe_show_begin\n'
            sudo -n dnctl pipe show "$PIPE_A" "$PIPE_B" 2>&1 || true
            printf 'dnctl_pipe_show_end\n'
            printf 'pf_anchor_rules_begin\n'
            sudo -n pfctl -a "$PF_ANCHOR" -sr 2>&1 || true
            printf 'pf_anchor_rules_end\n'
        } >"$artifact_dir/cleanup_after.txt" 2>&1 || true
        cp "$artifact_dir/cleanup_after.txt" \
            "$evidence_dir/cleanup_after_$run_id.txt" >/dev/null 2>&1 || true
        sudo -n chown -R "$(id -u):$(id -g)" "$artifact_dir" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT HUP INT TERM

sudo -v || fail "sudo authorization"
sudo_ready=1
if sudo dnctl pipe show "$PIPE_A" 2>/dev/null | grep -q "^$PIPE_A:"; then
    fail "dnctl pipe $PIPE_A already exists"
fi
if sudo dnctl pipe show "$PIPE_B" 2>/dev/null | grep -q "^$PIPE_B:"; then
    fail "dnctl pipe $PIPE_B already exists"
fi

sudo ifconfig feth0 create || fail "create feth0"
created0=1
sudo ifconfig feth1 create || fail "create feth1"
created1=1
sudo ifconfig feth1 peer feth0 || fail "pair feth interfaces"
sudo ifconfig feth0 inet 198.18.0.1 netmask 255.255.255.252 up ||
    fail "configure feth0"
sudo ifconfig feth1 inet 198.18.0.2 netmask 255.255.255.252 up ||
    fail "configure feth1"

cat >"$rules_file" <<EOF
dummynet out quick on feth0 proto 253 pipe $PIPE_A
dummynet out quick on feth1 proto 253 pipe $PIPE_B
dummynet out quick on feth0 proto tcp from 198.18.0.1 to 198.18.0.2 port $TCP_PORT pipe $PIPE_A
dummynet out quick on feth1 proto tcp from 198.18.0.2 port $TCP_PORT to 198.18.0.1 pipe $PIPE_B
EOF
pfctl -nf "$rules_file" >"$artifact_dir/pf_syntax.stdout" \
    2>"$artifact_dir/pf_syntax.stderr" || fail "PF syntax check"

sudo dnctl pipe "$PIPE_A" config delay "$DELAY_MS" plr "$PLR" ||
    fail "configure pipe $PIPE_A"
sudo dnctl pipe "$PIPE_B" config delay "$DELAY_MS" plr "$PLR" ||
    fail "configure pipe $PIPE_B"
sudo dnctl pipe show "$PIPE_A" "$PIPE_B" >"$artifact_dir/dnctl_pipes.txt" ||
    fail "record dnctl state"
sudo pfctl -a "$PF_ANCHOR" -f "$rules_file" >"$artifact_dir/pf_load.stdout" \
    2>"$artifact_dir/pf_load.stderr" || fail "load PF anchor"
pf_enable_output=$(sudo pfctl -E 2>&1) || fail "enable PF"
printf '%s\n' "$pf_enable_output" >"$artifact_dir/pf_enable.txt"
pf_token=$(printf '%s\n' "$pf_enable_output" | awk '/Token/ {print $3; exit}')
sudo pfctl -a "$PF_ANCHOR" -sr >"$artifact_dir/pf_anchor_rules.txt" ||
    fail "record PF anchor"

sudo "$VECTORNET_BENCH_RUNNER" custom-server \
    --interface feth1 \
    --local-custom-ip 198.19.0.2 \
    --peer-custom-ip 198.19.0.1 \
    --workload rtt \
    --payload-bytes "$PAYLOAD_BYTES" \
    --warmup-ms "$WARMUP_MS" \
    --duration-ms "$DURATION_MS" \
    --max-runtime-ms "$MAX_RUNTIME_MS" \
    --out "$artifact_dir/custom_server.json" \
    >"$artifact_dir/custom_server.stdout" \
    2>"$artifact_dir/custom_server.stderr" &
custom_server_pid=$!
sleep 1
sudo "$VECTORNET_BENCH_RUNNER" custom-client \
    --interface feth0 \
    --local-custom-ip 198.19.0.1 \
    --peer-custom-ip 198.19.0.2 \
    --workload rtt \
    --payload-bytes "$PAYLOAD_BYTES" \
    --warmup-ms "$WARMUP_MS" \
    --duration-ms "$DURATION_MS" \
    --max-runtime-ms "$MAX_RUNTIME_MS" \
    --out "$artifact_dir/custom_client.json" \
    >"$artifact_dir/custom_client.stdout" \
    2>"$artifact_dir/custom_client.stderr"
custom_client_exit=$?
wait_bounded "$custom_server_pid"
custom_server_exit=$?
custom_server_pid=

"$VECTORNET_BENCH_RUNNER" tcp-server \
    --bind 198.18.0.2 \
    --port "$TCP_PORT" \
    --workload rtt \
    --payload-bytes "$PAYLOAD_BYTES" \
    --warmup-ms "$WARMUP_MS" \
    --duration-ms "$DURATION_MS" \
    --max-runtime-ms "$MAX_RUNTIME_MS" \
    --out "$artifact_dir/tcp_server.json" \
    >"$artifact_dir/tcp_server.stdout" \
    2>"$artifact_dir/tcp_server.stderr" &
tcp_server_pid=$!
sleep 1
"$VECTORNET_BENCH_RUNNER" tcp-client \
    --bind 198.18.0.1 \
    --peer 198.18.0.2 \
    --port "$TCP_PORT" \
    --workload rtt \
    --payload-bytes "$PAYLOAD_BYTES" \
    --warmup-ms "$WARMUP_MS" \
    --duration-ms "$DURATION_MS" \
    --max-runtime-ms "$MAX_RUNTIME_MS" \
    --out "$artifact_dir/tcp_client.json" \
    >"$artifact_dir/tcp_client.stdout" \
    2>"$artifact_dir/tcp_client.stderr"
tcp_client_exit=$?
wait_bounded "$tcp_server_pid"
tcp_server_exit=$?
tcp_server_pid=

[ "$custom_client_exit" -eq 0 ] || fail "custom client exit $custom_client_exit"
[ "$custom_server_exit" -eq 0 ] || fail "custom server exit $custom_server_exit"
[ "$tcp_client_exit" -eq 0 ] || fail "tcp client exit $tcp_client_exit"
[ "$tcp_server_exit" -eq 0 ] || fail "tcp server exit $tcp_server_exit"
grep -q '"status":"pass"' "$artifact_dir/custom_client.json" ||
    fail "custom client did not pass"
grep -q '"status":"pass"' "$artifact_dir/custom_server.json" ||
    fail "custom server did not pass"
grep -q '"status":"pass"' "$artifact_dir/tcp_client.json" ||
    fail "tcp client did not pass"
grep -q '"status":"pass"' "$artifact_dir/tcp_server.json" ||
    fail "tcp server did not pass"

os_version=$(sw_vers -productVersion)
os_build=$(sw_vers -buildVersion)
kernel=$(uname -r)
chip=$(sysctl -n machdep.cpu.brand_string)
commit=$(DEVELOPER_DIR=/Library/Developer/CommandLineTools git rev-parse HEAD)
mtu0=$(ifconfig feth0 | awk '/mtu/ {for (i=1; i<=NF; i++) if ($i == "mtu") {print $(i+1); exit}}')
thermal=$(pmset -g therm | tr '\n' ';' | sed 's/"/'\''/g')

cat >"$artifact_dir/summary.json" <<EOF
{"phase":23,"gate":"feth-dummynet-pf-harness","actual_utc":"$run_id","source_commit":"$commit","macos":"$os_version","build":"$os_build","kernel":"$kernel","chip":"$chip","topology":"feth0/feth1","default_route_interface":"$default_iface","mtu":$mtu0,"pf_anchor":"$PF_ANCHOR","pipes":[$PIPE_A,$PIPE_B],"delay_ms":$DELAY_MS,"plr":$PLR,"payload_bytes":$PAYLOAD_BYTES,"warmup_ms":$WARMUP_MS,"duration_ms":$DURATION_MS,"trial_order":["custom-rtt","tcp-rtt"],"timestamp_sources":{"custom_primary":"application CLOCK_MONOTONIC RTT","custom_rx":"bpf_hdr.bh_tstamp diagnostic","tcp_primary":"application CLOCK_MONOTONIC RTT","tcp_rx":"SO_TIMESTAMP_MONOTONIC recvmsg cmsg diagnostic"},"core_pinning":"unsupported on Apple Silicon; not claimed","thermal":"$thermal","custom_client_exit":$custom_client_exit,"custom_server_exit":$custom_server_exit,"tcp_client_exit":$tcp_client_exit,"tcp_server_exit":$tcp_server_exit,"status":"pass"}
EOF

cp "$artifact_dir/custom_client.json" "$evidence_dir/custom_client_$run_id.json"
cp "$artifact_dir/custom_server.json" "$evidence_dir/custom_server_$run_id.json"
cp "$artifact_dir/tcp_client.json" "$evidence_dir/tcp_client_$run_id.json"
cp "$artifact_dir/tcp_server.json" "$evidence_dir/tcp_server_$run_id.json"
cp "$artifact_dir/summary.json" "$evidence_dir/summary_$run_id.json"
cp "$artifact_dir/dnctl_pipes.txt" "$evidence_dir/dnctl_pipes_$run_id.txt"
cp "$artifact_dir/pf_anchor_rules.txt" "$evidence_dir/pf_anchor_rules_$run_id.txt"

cat "$artifact_dir/summary.json"
printf '\nartifact=%s\n' "$artifact_dir"
printf 'evidence=%s\n' "$evidence_dir"

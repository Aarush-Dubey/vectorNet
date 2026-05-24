#!/bin/sh
set -u

fail() {
    printf '%s\n' "phase04 feth Ethernet failed: $*" >&2
    exit 1
}

wait_bounded() {
    process_id=$1
    attempts=0
    while kill -0 "$process_id" >/dev/null 2>&1 && [ "$attempts" -lt 15 ]; do
        attempts=$((attempts + 1))
        sleep 1
    done
    if kill -0 "$process_id" >/dev/null 2>&1; then
        sudo kill -TERM "$process_id" >/dev/null 2>&1 || true
        return 124
    fi
    wait "$process_id"
}

VECTORNET_LINK_PROBE=${VECTORNET_LINK_PROBE:-build/vectornet_link_probe}
VECTORNET_ETHERNET_PROBE=${VECTORNET_ETHERNET_PROBE:-build/vectornet_ethernet_probe}
ARTIFACT_ROOT=${VECTORNET_ARTIFACT_ROOT:-.vectornet-artifacts/phase04}

[ -x "$VECTORNET_LINK_PROBE" ] || fail "missing $VECTORNET_LINK_PROBE"
[ -x "$VECTORNET_ETHERNET_PROBE" ] || fail "missing $VECTORNET_ETHERNET_PROBE"
if ifconfig feth0 >/dev/null 2>&1 || ifconfig feth1 >/dev/null 2>&1; then
    fail "feth0 or feth1 already exists; refusing to alter it"
fi

run_id=$(date -u +%Y%m%dT%H%M%SZ)
artifact_dir="$ARTIFACT_ROOT/feth-ethernet-$run_id"
mkdir -p "$artifact_dir"
created0=0
created1=0
server_pid=
tcpdump_pid=

cleanup() {
    if [ -n "$server_pid" ] && kill -0 "$server_pid" >/dev/null 2>&1; then
        sudo kill -TERM "$server_pid" >/dev/null 2>&1 || true
    fi
    if [ -n "$tcpdump_pid" ] && kill -0 "$tcpdump_pid" >/dev/null 2>&1; then
        sudo kill -INT "$tcpdump_pid" >/dev/null 2>&1 || true
    fi
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

destination=$(sudo "$VECTORNET_LINK_PROBE" info --interface feth1 --mac-only) ||
    fail "read feth1 metadata"

sudo tcpdump -i feth0 -s 0 -U -w "$artifact_dir/phase04.pcap" \
    'ip proto 253' >"$artifact_dir/tcpdump.stdout" \
    2>"$artifact_dir/tcpdump.stderr" &
tcpdump_pid=$!
sudo "$VECTORNET_ETHERNET_PROBE" server --interface feth1 \
    >"$artifact_dir/server.json" 2>"$artifact_dir/server.stderr" &
server_pid=$!
sleep 1

sudo "$VECTORNET_ETHERNET_PROBE" client --interface feth0 \
    --destination "$destination" >"$artifact_dir/client.json" \
    2>"$artifact_dir/client.stderr" &
client_pid=$!
wait_bounded "$client_pid"
client_exit=$?
wait_bounded "$server_pid"
server_exit=$?
server_pid=
sudo kill -INT "$tcpdump_pid" >/dev/null 2>&1 || true
wait "$tcpdump_pid" || true
tcpdump_pid=
sudo chown -R "$(id -u):$(id -g)" "$artifact_dir"

[ "$client_exit" -eq 0 ] || fail "client exit $client_exit"
[ "$server_exit" -eq 0 ] || fail "server exit $server_exit"
/usr/bin/grep -q '"status":"pass"' "$artifact_dir/client.json" ||
    fail "client did not report pass"
/usr/bin/grep -q '"status":"pass"' "$artifact_dir/server.json" ||
    fail "server did not report pass"
/usr/bin/grep -q '"short_rejected_before_kernel":true' "$artifact_dir/client.json" ||
    fail "short frame was not rejected before kernel TX"
/usr/bin/grep -q '"vlan_rejected_before_kernel":true' "$artifact_dir/client.json" ||
    fail "VLAN frame was not rejected before kernel TX"
packet_count=$(tcpdump -nn -r "$artifact_dir/phase04.pcap" 2>/dev/null | wc -l | tr -d ' ')
[ "$packet_count" -ge 2 ] || fail "packet trace has only $packet_count records"

os_version=$(sw_vers -productVersion)
os_build=$(sw_vers -buildVersion)
kernel=$(uname -r)
chip=$(sysctl -n machdep.cpu.brand_string)
commit=$(DEVELOPER_DIR=/Library/Developer/CommandLineTools git rev-parse HEAD)
cat >"$artifact_dir/summary.json" <<EOF
{"phase":4,"gate":"Ethernet-parser-builder-feth-round-trip","actual_utc":"$run_id","commit":"$commit","macos":"$os_version","build":"$os_build","kernel":"$kernel","chip":"$chip","topology":"feth0/feth1","dlt":"DLT_EN10MB","bpf_filter":"local-or-broadcast ARP or IPv4 protocol 253","short_frame_unit_rejection":true,"vlan_frame_unit_rejection":true,"malformed_kernel_injection":false,"client_exit":$client_exit,"server_exit":$server_exit,"captured_packets":$packet_count,"packet_capture_committed":false,"packet_capture_note":"Local ignored pcap contains link-layer addresses.","status":"pass","pf":"not_applied","dummynet":"not_applied"}
EOF

cat "$artifact_dir/summary.json"
printf '\nartifact=%s\n' "$artifact_dir"

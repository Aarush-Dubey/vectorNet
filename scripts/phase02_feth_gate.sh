#!/bin/sh
set -u

fail() {
    printf '%s\n' "phase02 feth gate failed: $*" >&2
    exit 1
}

VECTORNET_BPF_PROBE=${VECTORNET_BPF_PROBE:-build/vectornet_link_probe}
ARTIFACT_ROOT=${VECTORNET_ARTIFACT_ROOT:-.vectornet-artifacts/phase02}

[ -x "$VECTORNET_BPF_PROBE" ] || fail "missing $VECTORNET_BPF_PROBE"
if ifconfig feth0 >/dev/null 2>&1 || ifconfig feth1 >/dev/null 2>&1; then
    fail "feth0 or feth1 already exists; refusing to alter it"
fi

run_id=$(date -u +%Y%m%dT%H%M%SZ)
artifact_dir="$ARTIFACT_ROOT/feth-gate-$run_id"
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
sudo "$VECTORNET_BPF_PROBE" info --interface feth0 >"$artifact_dir/feth0-bpf-info.json" ||
    fail "open BPF on feth0"

send_direction() {
    sender=$1
    receiver=$2
    label=$3
    destination=$(sudo "$VECTORNET_BPF_PROBE" info --interface "$receiver" --mac-only) ||
        return 1

    capture_file="$artifact_dir/$label.pcap"
    sudo /usr/sbin/tcpdump -i "$receiver" -c 1 -U -w "$capture_file" \
        'ether proto 0x88b5' >/dev/null 2>"$capture_file.stderr" &
    capture_pid=$!
    sleep 1

    sudo "$VECTORNET_BPF_PROBE" send --interface "$sender" --destination "$destination" \
        >"$artifact_dir/$label-send.json" 2>"$artifact_dir/$label-send.stderr"
    send_result=$?

    attempts=0
    while kill -0 "$capture_pid" >/dev/null 2>&1 && [ "$attempts" -lt 5 ]; do
        attempts=$((attempts + 1))
        sleep 1
    done
    if kill -0 "$capture_pid" >/dev/null 2>&1; then
        sudo kill -TERM "$capture_pid" >/dev/null 2>&1 || true
        wait "$capture_pid" >/dev/null 2>&1
        capture_result=124
    else
        wait "$capture_pid"
        capture_result=$?
    fi

    printf '%s:%s\n' "$send_result" "$capture_result" >"$artifact_dir/$label-status.txt"
    [ "$send_result" -eq 0 ] && [ "$capture_result" -eq 0 ]
}

forward=false
reverse=false
if send_direction feth0 feth1 feth0-to-feth1; then
    forward=true
fi
if send_direction feth1 feth0 feth1-to-feth0; then
    reverse=true
fi

IFS=: read -r forward_send_exit forward_capture_exit \
    <"$artifact_dir/feth0-to-feth1-status.txt"
IFS=: read -r reverse_send_exit reverse_capture_exit \
    <"$artifact_dir/feth1-to-feth0-status.txt"

if [ "$forward" = true ] && [ "$reverse" = true ]; then
    result=pass
else
    result=fail
fi

os_version=$(sw_vers -productVersion)
os_build=$(sw_vers -buildVersion)
kernel=$(uname -r)
chip=$(sysctl -n machdep.cpu.brand_string)
commit=$(DEVELOPER_DIR=/Library/Developer/CommandLineTools git rev-parse HEAD)
mtu=$(sed -E 's/.*"mtu":([0-9]+).*/\1/' "$artifact_dir/feth0-bpf-info.json")
bpf_bytes=$(sed -E 's/.*"bpf_buffer_bytes":([0-9]+).*/\1/' \
    "$artifact_dir/feth0-bpf-info.json")
cat >"$artifact_dir/summary.json" <<EOF
{"phase":2,"gate":"bidirectional-feth-frames","actual_utc":"$run_id","commit":"$commit","macos":"$os_version","build":"$os_build","kernel":"$kernel","chip":"$chip","topology":"feth0/feth1","mtu":$mtu,"bpf_buffer_bytes":$bpf_bytes,"dlt":"DLT_EN10MB","tx_api":"BPF","feth0_to_feth1":$forward,"feth0_send_exit":$forward_send_exit,"feth1_capture_exit":$forward_capture_exit,"feth1_to_feth0":$reverse,"feth1_send_exit":$reverse_send_exit,"feth0_capture_exit":$reverse_capture_exit,"status":"$result","pf":"not_applied","dummynet":"not_applied"}
EOF

cat "$artifact_dir/summary.json"
printf '\nartifact=%s\n' "$artifact_dir"
[ "$result" = pass ]

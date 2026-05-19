#!/bin/sh
set -u

fail() {
    printf '%s\n' "phase02 feth spike failed: $*" >&2
    exit 1
}

VECTORNET_BPF_PROBE=${VECTORNET_BPF_PROBE:-build/vectornet_link_probe}
VECTORNET_NDRV_PROBE=${VECTORNET_NDRV_PROBE:-build/vectornet_ndrv_probe}
ARTIFACT_ROOT=${VECTORNET_ARTIFACT_ROOT:-.vectornet-artifacts/phase02}

[ -x "$VECTORNET_BPF_PROBE" ] || fail "missing $VECTORNET_BPF_PROBE"
[ -x "$VECTORNET_NDRV_PROBE" ] || fail "missing $VECTORNET_NDRV_PROBE"
if ifconfig feth0 >/dev/null 2>&1 || ifconfig feth1 >/dev/null 2>&1; then
    fail "feth0 or feth1 already exists; refusing to alter it"
fi

run_id=$(date -u +%Y%m%dT%H%M%SZ)
artifact_dir="$ARTIFACT_ROOT/feth-spike-$run_id"
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
    fail "read feth1 metadata through BPF"
sudo "$VECTORNET_BPF_PROBE" info --interface feth0 >"$artifact_dir/feth0-bpf-info.json" ||
    fail "open BPF on feth0"
sudo "$VECTORNET_BPF_PROBE" info --interface feth1 >"$artifact_dir/feth1-bpf-info.json" ||
    fail "open BPF on feth1"

capture_test() {
    api=$1
    capture_file=$2
    send_log=$3
    shift 3

    sudo /usr/sbin/tcpdump -i feth1 -c 1 -U -w "$capture_file" \
        'ether proto 0x88b5' >/dev/null 2>"$capture_file.stderr" &
    capture_pid=$!
    sleep 1

    "$@" >"$send_log" 2>"$send_log.stderr"
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

    if [ "$send_result" -eq 0 ] && [ "$capture_result" -eq 0 ]; then
        printf '%s' true
    else
        printf '%s' false
    fi
    printf '%s:%s\n' "$send_result" "$capture_result" >"$artifact_dir/$api-status.txt"
}

bpf_delivered=$(capture_test \
    bpf \
    "$artifact_dir/bpf-tx.pcap" \
    "$artifact_dir/bpf-send.json" \
    sudo "$VECTORNET_BPF_PROBE" send --interface feth0 --destination "$destination")

ndrv_delivered=$(capture_test \
    ndrv \
    "$artifact_dir/ndrv-tx.pcap" \
    "$artifact_dir/ndrv-send.json" \
    sudo "$VECTORNET_NDRV_PROBE" --interface feth0 "$destination")

IFS=: read -r bpf_send_exit bpf_capture_exit <"$artifact_dir/bpf-status.txt"
IFS=: read -r ndrv_send_exit ndrv_capture_exit <"$artifact_dir/ndrv-status.txt"

if [ "$bpf_delivered" = true ]; then
    selected_tx=BPF
elif [ "$ndrv_delivered" = true ]; then
    selected_tx=AF_NDRV
else
    selected_tx=none
fi

os_version=$(sw_vers -productVersion)
os_build=$(sw_vers -buildVersion)
kernel=$(uname -r)
sdk=$(DEVELOPER_DIR=/Library/Developer/CommandLineTools xcrun --sdk macosx --show-sdk-version)
chip=$(sysctl -n machdep.cpu.brand_string)
mtu=$(sed -E 's/.*"mtu":([0-9]+).*/\1/' "$artifact_dir/feth0-bpf-info.json")
bpf_bytes=$(sed -E 's/.*"bpf_buffer_bytes":([0-9]+).*/\1/' \
    "$artifact_dir/feth0-bpf-info.json")
cat >"$artifact_dir/summary.json" <<EOF
{"phase":2,"spike":"feth-tx-rx","actual_utc":"$run_id","macos":"$os_version","build":"$os_build","kernel":"$kernel","sdk":"$sdk","chip":"$chip","topology":"feth0/feth1","mtu":$mtu,"bpf_buffer_bytes":$bpf_bytes,"bpf_rx_dlt":"DLT_EN10MB","bpf_tx_send_exit":$bpf_send_exit,"bpf_rx_capture_exit":$bpf_capture_exit,"bpf_tx_delivered":$bpf_delivered,"af_ndrv_send_exit":$ndrv_send_exit,"af_ndrv_rx_capture_exit":$ndrv_capture_exit,"af_ndrv_tx_delivered":$ndrv_delivered,"selected_tx":"$selected_tx","pf":"not_applied","dummynet":"not_applied"}
EOF

cat "$artifact_dir/summary.json"
printf '\nartifact=%s\n' "$artifact_dir"
[ "$selected_tx" != none ] || exit 1

#!/bin/sh
set -u

fail() {
    printf '%s\n' "phase08 fragment reference failed: $*" >&2
    exit 1
}

VECTORNET_FRAGMENT_PROBE=${VECTORNET_FRAGMENT_PROBE:-build/vectornet_fragment_probe}
ARTIFACT_ROOT=${VECTORNET_ARTIFACT_ROOT:-.vectornet-artifacts/phase08}
[ -x "$VECTORNET_FRAGMENT_PROBE" ] || fail "missing $VECTORNET_FRAGMENT_PROBE"

run_id=$(date -u +%Y%m%dT%H%M%SZ)
artifact_dir="$ARTIFACT_ROOT/fragment-reference-$run_id"
mkdir -p "$artifact_dir"
"$VECTORNET_FRAGMENT_PROBE" "$artifact_dir/fragments.pcap" \
    >"$artifact_dir/probe.json" 2>"$artifact_dir/probe.stderr" ||
    fail "fragment probe"
tcpdump -nn -vvv -r "$artifact_dir/fragments.pcap" \
    >"$artifact_dir/tcpdump.txt" 2>"$artifact_dir/tcpdump.stderr" ||
    fail "tcpdump decode"

[ "$(/usr/bin/grep -c ' IP (' "$artifact_dir/tcpdump.txt")" -eq 3 ] ||
    fail "tcpdump fragment count"
/usr/bin/grep -q 'id 4660, offset 0' "$artifact_dir/tcpdump.txt" ||
    fail "missing offset 0"
/usr/bin/grep -q 'id 4660, offset 1480' "$artifact_dir/tcpdump.txt" ||
    fail "missing offset 1480"
/usr/bin/grep -q 'id 4660, offset 2960' "$artifact_dir/tcpdump.txt" ||
    fail "missing offset 2960"
/usr/bin/grep -q '"packet_bytes":\[1500,1500,1060\]' "$artifact_dir/probe.json" ||
    fail "probe sizes"

os_version=$(sw_vers -productVersion)
os_build=$(sw_vers -buildVersion)
kernel=$(uname -r)
commit=$(DEVELOPER_DIR=/Library/Developer/CommandLineTools git rev-parse HEAD)
cat >"$artifact_dir/summary.json" <<EOF
{"phase":8,"gate":"IPv4-fragment-reference","actual_utc":"$run_id","commit":"$commit","macos":"$os_version","build":"$os_build","kernel":"$kernel","capture_link_type":"DLT_RAW","mtu":1500,"payload_bytes":4000,"fragment_packet_bytes":[1500,1500,1060],"fragment_offset_bytes":[0,1480,2960],"identification":4660,"reference":"system tcpdump offline decode","pcap_committed":false,"status":"pass"}
EOF
cat "$artifact_dir/summary.json"
printf '\nartifact=%s\n' "$artifact_dir"

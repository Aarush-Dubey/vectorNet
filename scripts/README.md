# Integration scripts

`phase02_feth_spike.sh` creates `feth0`/`feth1`, verifies BPF RX uses
`DLT_EN10MB`, compares BPF and `AF_NDRV` TX delivery, then destroys both
interfaces. Run it before selecting the Darwin TX path:

```sh
scripts/phase02_feth_spike.sh
```

`phase02_feth_gate.sh` then sends experimental EtherType `0x88B5` frames in both
directions. Separate `tcpdump` receiver and vectorNet sender processes bind to
opposite sides:

```sh
scripts/phase02_feth_gate.sh
```

Both scripts refuse pre-existing `feth0`/`feth1` interfaces. Captures remain under
ignored `.vectornet-artifacts/`; summaries contain no MAC address. A later optional
cross-host confirmation belongs to Phase 25 and must remain separate from canonical
feth results.

`phase03_feth_batch.sh` exercises production `kqueue`/BPF batch reads, checks
`BIOCGSTATS`, records expected `dtruss`-under-SIP evidence, then captures the
read/`kevent`/write timeline with Instruments System Trace. It commits only the
sanitized CSV; raw trace bundles stay ignored because they contain UUID metadata:

```sh
scripts/phase03_feth_batch.sh
```

`phase04_feth_ethernet.sh` runs two filtered Ethernet endpoints across feth. It
verifies short and VLAN frames are rejected in userspace before BPF TX, then runs a
valid IPv4-protocol-253 echo. Malformed frames never enter feth. Script records both
process logs and keeps its address-bearing packet capture ignored:

```sh
scripts/phase04_feth_ethernet.sh
```

Future scripts that open BPF devices or alter `dnctl`/PF state must require explicit
`sudo`, scope rules narrowly, snapshot prior state, and restore it on success, failure,
or interruption. Unit tests must never call these scripts.

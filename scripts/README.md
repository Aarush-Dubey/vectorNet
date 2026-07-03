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

`phase08_fragment_reference.sh` needs no sudo. It emits a DLT_RAW pcap, decodes the
fragment set with system `tcpdump`, and validates sizes plus byte offsets:

```sh
scripts/phase08_fragment_reference.sh
```

`phase10_reassembly_fuzz.sh` uses Homebrew LLVM's upstream libFuzzer runtime with
ASan/UBSan. The Xcode 26.6 package on the measured host lacks the runtime archive:

```sh
brew install llvm
scripts/phase10_reassembly_fuzz.sh
```

`phase11_allocation_gate.sh` injects the project DYLD allocation interposer into a
sustained packet-pool loop. It needs no sudo and exits nonzero unless every hot-window
allocation and deallocation counter is zero:

```sh
scripts/phase11_allocation_gate.sh
```

`phase12_tsan.sh` builds only the owner-pool SPSC stress target with Apple Clang's
ThreadSanitizer and aborts on the first race report:

```sh
scripts/phase12_tsan.sh
```

`phase22_instrument_gate.sh` runs a labeled `CLOCK_MONOTONIC` clock-path self-check
and writes full 64-bucket CSV/JSONL under ignored `.vectornet-artifacts/`. It is not
a network-latency benchmark:

```sh
scripts/phase22_instrument_gate.sh
```

Future scripts that open BPF devices or alter `dnctl`/PF state must require explicit
`sudo`, scope rules narrowly, snapshot prior state, and restore it on success, failure,
or interruption. Unit tests must never call these scripts.

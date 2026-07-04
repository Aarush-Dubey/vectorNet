# Benchmark artifacts and evidence

Benchmark scripts generate raw output locally under ignored artifact directories.
The cleaned public repository keeps the harnesses and documentation, but does not
publish machine-specific evidence logs, packet captures, Instruments bundles, panic
reports, or interface metadata.

Correctness-gate records are not transport-performance results. Allocation-interposer
runs establish the zero-hot-window-allocation invariant only; operation counts are
not latency or throughput claims.

The histogram gate validates fixed histogram/export plumbing and records the
application monotonic timestamp label. Its values are not packet,
application-message, or network RTT measurements.

System Trace runs use Instruments through `xctrace`. Raw `.trace` bundles and XML
stay local because they can contain device and binary UUIDs. `dtruss` is expected to
produce zero syscall rows under default SIP on current macOS; SIP is not weakened.

Safety evidence for malformed raw BPF writes stays local because panic reports can
contain machine UUID metadata. Production TX rejects malformed frame lengths before
the syscall.

Primary runs use `feth0`/`feth1` and must record macOS/XNU build, XNU CUBIC baseline,
chip, feth MTU, dummynet/PF rules, timestamp source, thermal state, trial ordering,
sample count, and variance. Proxy measurements must be labeled as proxies and cannot
support cache-miss claims.

The PF/dummynet harness is a smoke gate for scoped pipe/anchor setup, teardown,
identical payload/duration/order, and timestamp labels. Instruments CPU Counters
support is treated as capability evidence; without a direct HITM/cache-to-cache
event, packet-pool measurements are wall-clock/throughput proxies only.

Optional cross-host confirmation records both Macs and NICs in a separate report
subsection. Its samples never enter canonical feth aggregates.

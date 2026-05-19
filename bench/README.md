# Benchmark artifacts and evidence

No benchmark result exists through Phase 02. The `evidence/phase02/` files are
link-API selection and correctness-gate records, not performance results.

Future primary runs use `feth0`/`feth1` and must commit raw output identifying the
macOS/XNU build, XNU CUBIC baseline, chip, feth MTU, dummynet/PF rules, timestamp
source, thermal state, trial ordering, sample count, and variance. Proxy measurements
must be labeled as proxies and cannot support cache-miss claims.

Optional cross-host confirmation records both Macs and NICs in a separate report
subsection. Its samples never enter canonical feth aggregates.

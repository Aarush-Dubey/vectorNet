# Benchmark artifacts and evidence

No benchmark result exists through Phase 03. Evidence files are correctness-gate
records, not performance results.

Phase 03 commits a sanitized Instruments System Trace syscall timeline. Raw `.trace`
bundles and XML stay local because they contain device and binary UUIDs. The committed
CSV retains each relevant syscall's relative start time, duration, and return value.
`dtruss` logs record its expected zero-row result under default SIP; SIP was not
weakened.

Future primary runs use `feth0`/`feth1` and must commit raw output identifying the
macOS/XNU build, XNU CUBIC baseline, chip, feth MTU, dummynet/PF rules, timestamp
source, thermal state, trial ordering, sample count, and variance. Proxy measurements
must be labeled as proxies and cannot support cache-miss claims.

Optional cross-host confirmation records both Macs and NICs in a separate report
subsection. Its samples never enter canonical feth aggregates.

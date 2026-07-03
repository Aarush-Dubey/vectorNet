# Darwin instrumentation contract

- Custom RX uses `bpf_hdr.bh_tstamp`; it is tagged as the BPF capture source.
- Custom TX records `CLOCK_MONOTONIC` immediately before and after BPF `write()`.
  This brackets syscall handoff only. macOS exposes no hardware TX completion here.
- Kernel-TCP enables `SO_TIMESTAMP_MONOTONIC` and parses
  `SCM_TIMESTAMP_MONOTONIC` from `recvmsg()` control messages.
- Primary Phase-25 RTT uses application `CLOCK_MONOTONIC` begin/end timestamps in
  one client process, so both transports share one clock.

These sources mark different capture points. Packet timestamps are diagnostics and
must never be presented as equal-fidelity one-way latency or hardware-grade time.
The fixed 64-bucket logarithmic histogram allocates no storage while recording and
exports the complete bucket array to CSV or JSONL after the hot window.

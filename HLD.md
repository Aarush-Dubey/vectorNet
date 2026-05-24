# High-Level Design — Userspace Network Stack over macOS BPF

Companion to `AGENTS.md` (25-phase build plan) and `LLD.md` (module-level design).
This document covers architecture, data flow, and the decisions that shape them —
not wire formats or struct layouts, which live in the LLD.

## 1. Purpose & scope

Build a userspace network stack that talks raw Ethernet through Darwin Berkeley
Packet Filter devices (`/dev/bpf*`), bypassing the kernel's TCP/IP stack entirely,
implementing:

- Link layer: frame TX/RX, ARP
- Network layer: IPv4 fragmentation/reassembly
- Transport layer: a custom protocol with SACK-based selective retransmission and
  AIMD congestion control
- A zero-hot-path-allocation packet pipeline underneath all of it

**Goal**: test the hypothesis that a purpose-built transport can trade throughput
for lower tail latency under loss, using reproducible measurements rather than
assertion.

**Non-goals**: NAT, routing (single-hop / same-broadcast-domain only), IPv6, TLS,
congestion control beyond AIMD (no CUBIC/BBR-style implementation), multi-homing.

## 2. System architecture

```
                         ┌─────────────────────────────┐
                         │      Application / bench     │
                         └───────────────┬──────────────┘
                                          │ send(bytes) / on_recv(bytes)
                         ┌───────────────▼──────────────┐
                         │      Transport (src/transport) │
                         │  conn state machine, SACK,     │
                         │  RTO estimator, AIMD            │
                         └───────────────┬──────────────┘
                                          │ IP payload
                         ┌───────────────▼──────────────┐
                         │       Network (src/net)        │
                         │  IPv4 header, fragmentation,   │
                         │  reassembly                    │
                         └───────────────┬──────────────┘
                                          │ Ethernet payload
                         ┌───────────────▼──────────────┐
                         │        Link (src/link)         │
                         │  Darwin buffered link I/O,      │
                         │  ARP resolve + cache            │
                         └───────────────┬──────────────┘
                                          │ raw frames
                         ┌───────────────▼──────────────┐
                         │  feth peer / optional real NIC  │
                         └─────────────────────────────┘

        ┌───────────────────────────────────────────────┐
        │   Cross-cutting: src/alloc (pool allocator)     │
        │   used by every layer on the RX/TX hot path      │
        └───────────────────────────────────────────────┘

        ┌───────────────────────────────────────────────┐
        │   src/instrument: BPF/socket clocks, histograms  │
        │   bench/: dummynet/PF, Instruments, reports      │
        └───────────────────────────────────────────────┘
```

Layers are strictly downward-calling on TX and upward-calling (via registered
callbacks, not virtual dispatch) on RX — no layer reaches across another to talk
to the one below it. This mirrors the kernel's own layering so the design is easy
to reason about and easy to compare fairly against kernel TCP.

## 3. Component responsibilities

| Component | Owns | Does not own |
|---|---|---|
| `src/link` | BPF lifecycle, buffered frame TX/RX, ARP cache/resolution | IP semantics, retransmission |
| `src/net` | IPv4 header (de)serialization, fragmentation, reassembly + timeout | MAC resolution, congestion control |
| `src/alloc` | Packet buffer lifecycle (acquire/release), cache-line layout | Packet *contents* |
| `src/transport` | Connection state, SACK generation/processing, RTO, AIMD, retransmit queue | Framing below IP, MAC resolution |
| `src/instrument` | Timestamping, latency histograms | Benchmark orchestration |
| `bench` | dummynet/PF scenarios, Instruments/proxy runs, baseline comparison, report generation | Any stack logic |

## 4. Data flow

### TX path (application → wire)
1. Application calls `transport::send(conn, bytes)`.
2. Transport segments `bytes` per current cwnd, assigns sequence numbers, pushes
   segments into the retransmission queue (Phase 15), and hands each to `net`.
3. `net` fragments if the segment exceeds link MTU, builds IPv4 headers, hands each
   fragment to `link`.
4. `link` resolves destination MAC (cache hit in the common case), acquires a
   buffer from `alloc`'s pool, builds the complete Ethernet frame in place, and
   writes it through the Phase-02-selected Darwin TX descriptor.
5. `instrument` brackets the selected TX syscall with `CLOCK_MONOTONIC` timestamps.
   This measures userspace hand-off plus syscall overhead, not NIC transmission.

### RX path (wire → application)
1. `link` waits through `kqueue`, reads a negotiated BPF buffer, and walks its
   aligned `bpf_hdr` records. Each record carries a kernel-assigned capture timestamp.
2. ARP frames are handled inline (cache update) and never propagate above `link`.
3. IP frames are handed to `net`: single fragments pass straight through; multi-
   fragment datagrams accumulate in the reassembly table until complete or timed out.
4. Complete IP payloads are handed to `transport`, which updates the receive
   window, generates cumulative-ack + SACK blocks, and delivers in-order bytes to
   the application callback.
5. Buffers are released back to `alloc`'s pool once no layer holds a reference —
   never freed via general-purpose allocation.

### Loss-recovery path (the part the benchmark is built around)
- Receiver-side gaps become SACK blocks (Phase 16) sent on the next outgoing ack.
- Sender marks SACK-confirmed ranges and retransmits only actual holes (Phase 17),
  not everything past the first loss — this is the throughput-preserving
  mechanism that a plain cumulative-ACK/go-back-N design lacks.
- Fast retransmit (Phase 18) or RTO expiry (Phase 19) triggers the actual resend;
  AIMD's multiplicative decrease (Phase 20–21) reacts to whichever loss signal
  fired, per the policy documented in `src/transport/README.md`.

## 5. Threading & concurrency model

- **RX thread**: owns the BPF/`kqueue` receive loop and everything up through
  reassembly.
- **TX thread**: owns retransmission-queue draining and link writes. Separate from
  RX to avoid one direction's syscalls stalling the other.
- **Timer thread** (or timer wheel driven off a lightweight event loop): drives
  RTO expiry checks and reassembly-timeout sweeps — decoupled from the data-path
  threads so a timer check never blocks a packet in flight.
- Cross-thread handoff (buffer pool freelist, retransmission queue) uses lock-free
  structures (Phase 12) — no mutex sits between RX/TX threads and the shared pool.
- This is a **single-connection-per-process** model for the initial build (matches
  the benchmark scenario); multi-connection sharding is an explicit non-goal
  unless a later phase adds it.

## 6. Key design decisions

| Decision | Alternatives considered | Rationale |
|---|---|---|
| Darwin BPF RX plus measured feth TX API over Network Extension/DriverKit | Network Extension packet tunnel, DriverKit | BPF exposes raw Ethernet capture without an application extension or custom driver. Phase 02 measures BPF and `AF_NDRV` TX on the selected kernel before choosing; no third-party historical result is assumed. The shipped path is buffered and copied. |
| Custom transport vs. reusing an existing protocol (QUIC, SCTP) | QUIC, SCTP, raw UDP + manual reliability | The point of the project is the transport internals (SACK/RTO/AIMD) being hand-built and measurable — reusing an existing implementation would remove the thing being demonstrated |
| Pool allocator vs. general-purpose allocator with tuning | `tcmalloc`/`jemalloc` tuning, arena allocators | Hot-path allocation-free is a hard, verifiable claim (zero `malloc` calls) that a tuned general allocator cannot give as cleanly. Instruments counters or labeled wall-clock/throughput proxies evaluate its cost without inventing unavailable HITM data. |
| Explicit RTO/Karn/AIMD per RFC 6298 rather than a simplified timer | Fixed timeout, no Karn's exclusion | A fixed timeout invalidates any latency-under-loss comparison against real TCP, since real TCP doesn't use one; Karn's exclusion specifically matters because the benchmark scenario *is* a loss scenario |
| macOS XNU TCP CUBIC as the sole baseline | Compare against multiple congestion control algorithms | One precisely named, fixed macOS/XNU build and CUBIC baseline keeps the benchmark honest and repeatable; comparing against several would spread effort thin and dilute the core claim |

## 7. Non-functional targets (hypotheses until Phase 25 confirms them)

These are **targets to validate**, not committed results — see `AGENTS.md` Phase
22–25 exit criteria. Do not promote any of these to "achieved" language until a
`bench/` run backs it.

- Lower client-observed p99 application RTT than macOS XNU TCP CUBIC under a
  defined dummynet loss/delay profile, at a bounded throughput cost.
- Lower measured cache-related PMU cost after the pool allocator lands only when
  Instruments exposes a directly relevant counter. Otherwise, lower wall-clock cost
  or higher throughput is a labeled proxy hypothesis, never a cache-miss claim.
- Zero heap allocation calls observed on the RX/TX hot path under sustained load.

### 7.1 Platform note: Linux vs macOS

The platform change is deliberate. It preserves layers and protocol behavior while
accepting lower observability and packet-I/O fidelity where Darwin exposes less.

| Linux design point | macOS/Darwin choice | Fidelity limit |
|---|---|---|
| `AF_PACKET` raw socket | Open `/dev/bpf*`; bind with `BIOCSETIF` | Requires elevated privilege |
| `PACKET_MMAP` / `TPACKET_V3` | Large `BIOCSBLEN` plus buffered `read()`/`write()` | Kernel/userspace copies remain; no zero-copy parity claim |
| Kernel-supplied Ethernet header | `BIOCSHDRCMPLT`, `BIOCPROMISC`, `BIOCSSEESENT(0)` | Stack supplies the full header and suppresses its own writes |
| `SO_TIMESTAMPING` hardware/software path | BPF `bh_tstamp` for custom RX; monotonic bracketing for custom TX; `SO_TIMESTAMP_MONOTONIC` cmsg for TCP RX | No BPF hardware TX completion; timestamp mechanisms differ |
| `tc netem` | `dnctl` pipes attached through `pfctl` dummynet rules | No `ipfw`; only measured pipe behavior may be claimed |
| `perf c2c` HITM data | Instruments Counters where relevant events exist | No direct equivalent; proxy fallback cannot support cache-miss claims |
| `taskset`, `isolcpus`, performance governor | No replacement | Apple Silicon scheduling/frequency cannot be pinned equivalently |
| veth pair | Paired `feth0`/`feth1` interfaces, available since macOS 10.13 | Real Ethernet framing (`DLT_EN10MB`) on one Mac; no physical switch or propagation behavior |

Phase 02 owns an explicit runtime spike because public Apple documentation does not
promise which injection API reliably feeds a paired feth interface across every
macOS release. It creates the pair, verifies BPF RX reports `DLT_EN10MB`, attempts a
complete-frame BPF write, attempts an `AF_NDRV` send, and records which frame BPF RX
actually observes. Historical third-party findings are context only. The production
TX path follows the committed observation from the current OS build.

**Observed selection (2026-07-17 UTC):** on macOS 26.5.1 build 25F80, XNU
25.5.0, and SDK 26.2, BPF RX reported `DLT_EN10MB`. A 60-byte complete frame
written through BPF on `feth0` was captured on `feth1`. A connected `AF_NDRV`
socket also accepted a 60-byte send, but BPF RX captured no matching frame before
the bounded timeout. Therefore this build selects BPF for both RX and TX. This is
not generalized to other macOS builds; rerun the spike after an OS/SDK change.
Sanitized raw evidence lives in
`bench/evidence/phase02/feth_io_spike_20260717T170204Z.json`; packet captures remain
uncommitted because project policy excludes link-layer addresses from committed logs.

Default SIP on the selected macOS build leaves `dtruss` with zero syscall rows for
both Apple and third-party binaries. Phase 03 commits that unsupported-tool evidence
and uses Instruments System Trace through `xctrace` for the required syscall/copy
timeline. This is a disclosed tooling substitution; SIP remains enabled.

On macOS 26.5.1 build 25F80, writing a 10-byte raw frame through BPF into feth
reproducibly triggered a kernel mbuf-validity panic (`len -4`, `rcvif feth1`). Raw
TX therefore rejects frames shorter than the 14-byte Ethernet header before
`write()`. Short/VLAN rejection tests stay in userspace; feth receives valid framing
only. Raw panic reports remain local because they contain machine UUID metadata.

Darwin's public BPF header currently exposes buffered BPF controls but not
`BIOCSETZBUF`, `BIOCROTZBUF`, or `BIOCGETZMAX`. The post-Phase-03 compile probe on
branch `spike/darwin-bpf-zbuf` confirmed all three absent from selected macOS 26.5
SDK headers, so zbuf promotion is rejected. Main path stays buffered unless a future
supported, measured implementation earns promotion in a later numbered phase;
FreeBSD ioctl values are never copied into Darwin code.

### 7.2 Canonical topology and result ownership

The canonical development, CI integration, correctness, and Phase 22–25 benchmark
topology is a single Mac with `feth0` peered to `feth1`. Sender and receiver are
separate processes bound to opposite sides. This exercises the complete Ethernet
header path; `lo0` is forbidden for link integration because its
`DLT_NULL`/`DLT_LOOP` framing would bypass that path. `dnctl`/PF rules attach to the
two feth interfaces exactly as they would to physical interfaces.

`bench/report.md` primary numbers come only from feth runs. A later two-Mac Wi-Fi or
ad hoc run is optional and appears only under "cross-host confirmation." Its samples
stay separate because Wi-Fi ARQ changes loss and latency behavior. Meaningful
disagreement must be reported; controlled feth results remain primary rather than
choosing whichever topology looks better. feth does not model a real switch or real
propagation delay, so cross-host confirmation remains useful but never blocking.

## 8. External interfaces

- **Kernel/link**: Darwin BPF RX API, `BIOCSBLEN`, `BIOCSETIF`,
  `BIOCSHDRCMPLT`, `BIOCPROMISC`, `BIOCSSEESENT(0)`, `BIOCIMMEDIATE`, and
  `kqueue`, plus only the feth TX API selected by the Phase-02 runtime spike. No
  interaction with the kernel's own IP/TCP stack for custom frames.
- **Timestamping**: BPF capture headers on custom RX, `CLOCK_MONOTONIC` around
  custom TX writes, and `SO_TIMESTAMP_MONOTONIC`/`recvmsg()` control messages for
  kernel-TCP RX. These sources are recorded separately, never presented as equal.
- **Test harness**: dedicated `dnctl` pipes and `pfctl` dummynet rules applied
  symmetrically to `feth0`/`feth1`, with previous state restored after each run.
- **Profiling**: Instruments Counters where supported; otherwise committed
  wall-clock/throughput proxy data labeled as such.
- **CI topology**: unit tests need no privilege. Privileged integration jobs create
  a temporary feth pair; no VM or `vmnet.framework` stand-in is required.

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Benchmark numbers get written before being measured | `AGENTS.md` hard rule: no claim without a committed `bench/` log backing it |
| ARP-miss stalls masquerade as transport-layer latency | Phase 06 pending-queue design so ARP resolution never silently drops/delays a segment |
| IP-layer bugs (overlap handling) get misattributed to the transport's SACK logic | Phase 10 fuzz test isolates reassembly correctness before transport work begins |
| Unfair baseline comparison (different topology/dummynet parameters per path) | Phase 23 records identical feth pair, PF/dummynet settings, payload, duration, and interleaved trial order; lack of core pinning remains explicit |
| feth injection behavior changes across macOS releases | Phase 02 re-runs BPF-vs-`AF_NDRV` TX spike and commits observed delivery before selecting an API |
| Lock-free allocator/queue introduces subtle races | TSan-clean requirement in Phase 12 exit criteria before proceeding |

See `LLD.md` for per-module data structures, wire formats, and algorithms.

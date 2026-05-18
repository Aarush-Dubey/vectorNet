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
                         │  Darwin BPF buffered I/O,       │
                         │  ARP resolve + cache            │
                         └───────────────┬──────────────┘
                                          │ raw frames
                         ┌───────────────▼──────────────┐
                         │         NIC (kernel driver)     │
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
   writes it to the bound BPF descriptor.
5. `instrument` brackets the BPF `write()` with `CLOCK_MONOTONIC` timestamps.
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
- **TX thread**: owns retransmission-queue draining and BPF writes. Separate from
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
| Darwin BPF over Network Extension/DriverKit | Network Extension packet tunnel, DriverKit | BPF exposes raw Ethernet through stable Darwin interfaces without adding an application extension or custom driver. The shipped path is buffered and copied; it is not claimed to match Linux zero-copy ring fidelity. |
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
| veth pair | Two physical Macs over real Ethernet | vmnet-backed interfaces are CI-only, never benchmark evidence |

Darwin's public BPF header currently exposes buffered BPF controls but not
`BIOCSETZBUF`, `BIOCROTZBUF`, or `BIOCGETZMAX`. A separate post-Phase-03 spike may
probe the selected SDK and kernel. The main path stays buffered unless a supported,
measured implementation earns promotion in a later numbered phase; FreeBSD ioctl
values are never copied into Darwin code.

## 8. External interfaces

- **Kernel/link**: Darwin BPF device API, `BIOCSBLEN`, `BIOCSETIF`,
  `BIOCSHDRCMPLT`, `BIOCPROMISC`, `BIOCSSEESENT(0)`, `BIOCIMMEDIATE`, and
  `kqueue`. No interaction with the kernel's own IP/TCP stack for custom frames.
- **Timestamping**: BPF capture headers on custom RX, `CLOCK_MONOTONIC` around
  custom TX writes, and `SO_TIMESTAMP_MONOTONIC`/`recvmsg()` control messages for
  kernel-TCP RX. These sources are recorded separately, never presented as equal.
- **Test harness**: dedicated `dnctl` pipes and `pfctl` dummynet rules applied
  symmetrically on two physical Macs, with previous state restored after each run.
- **Profiling**: Instruments Counters where supported; otherwise committed
  wall-clock/throughput proxy data labeled as such.
- **CI topology**: unit tests need no privilege. A `vmnet.framework`-backed
  interface may exercise link integration in CI, but cannot produce benchmark data.

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Benchmark numbers get written before being measured | `AGENTS.md` hard rule: no claim without a committed `bench/` log backing it |
| ARP-miss stalls masquerade as transport-layer latency | Phase 06 pending-queue design so ARP resolution never silently drops/delays a segment |
| IP-layer bugs (overlap handling) get misattributed to the transport's SACK logic | Phase 10 fuzz test isolates reassembly correctness before transport work begins |
| Unfair baseline comparison (different OS/NIC/dummynet parameters per path) | Phase 23 records identical PF/dummynet settings, Ethernet path, payload, duration, and interleaved trial order; lack of core pinning remains explicit |
| Lock-free allocator/queue introduces subtle races | TSan-clean requirement in Phase 12 exit criteria before proceeding |

See `LLD.md` for per-module data structures, wire formats, and algorithms.

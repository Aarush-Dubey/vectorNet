# High-Level Design — Userspace Network Stack over macOS BPF

This document explains what vectorNet is building, how the major subsystems fit
together, and why the macOS-specific architecture looks the way it does. The
low-level data structures, wire formats, and algorithms live in `LLD.md`.

## 1. Purpose & scope

vectorNet is a C++20 userspace network stack for macOS on Apple Silicon. It talks
directly to raw Ethernet through Darwin Berkeley Packet Filter devices (`/dev/bpf*`)
on a local `feth` pair and bypasses the kernel TCP/IP stack for its custom protocol.
The stack implements:

- Link layer: frame TX/RX, ARP
- Network layer: IPv4 fragmentation/reassembly
- Transport layer: a custom protocol with SACK-based selective retransmission and
  AIMD congestion control
- A zero-hot-path-allocation packet pipeline underneath all of it

The engineering goal is to make the full packet path visible and controllable:
Ethernet framing, ARP, IPv4 fragmentation, retransmission, congestion control,
allocation behavior, and benchmark instrumentation are all owned in the repo rather
than hidden inside kernel TCP.

The measurement goal is to test whether a purpose-built SACK transport can trade
throughput for lower tail latency under controlled loss. Any performance claim must
come from a reproducible benchmark run and must name the TCP baseline, topology,
timestamp source, and impairment settings.

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
2. Transport segments `bytes` per current congestion window, assigns sequence
   numbers, stores unacknowledged segments in the retransmission queue, and hands
   each packet to `net`.
3. `net` fragments if the segment exceeds link MTU, builds IPv4 headers, hands each
   fragment to `link`.
4. `link` resolves destination MAC (cache hit in the common case), acquires a
   buffer from `alloc`'s pool, builds the complete Ethernet frame in place, and
   writes it through the Darwin TX descriptor selected by the runtime feth probe.
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
- Receiver-side gaps become SACK blocks sent on the next outgoing ack.
- Sender marks SACK-confirmed ranges and retransmits only actual holes,
  not everything past the first loss — this is the throughput-preserving
  mechanism that a plain cumulative-ACK/go-back-N design lacks.
- Fast retransmit or RTO expiry triggers the actual resend; AIMD's multiplicative
  decrease reacts to whichever loss signal
  fired, per the policy documented in `src/transport/README.md`.

## 5. Threading & concurrency model

- **RX thread**: owns the BPF/`kqueue` receive loop and everything up through
  reassembly.
- **TX thread**: owns retransmission-queue draining and link writes. Separate from
  RX to avoid one direction's syscalls stalling the other.
- **Timers** live in the relevant owner thread's `kqueue`: RX owns reassembly
  timeout sweeps; TX owns retransmission and congestion timers. There is no third
  timer thread.
- Cross-thread traffic uses bounded SPSC rings with cache-line-separated cursors.
  Pools remain owner-local; a reverse SPSC ring returns buffers to their owner.
  Application→TX and RX→TX rings signal the TX kqueue through `EVFILT_USER`. No
  mutex or 128-bit tagged CAS sits on the handoff path.
- This is a **single-connection-per-process** model for the current benchmark
  shape; multi-connection sharding is an explicit non-goal for this implementation.

## 6. Key design decisions

| Decision | Alternatives considered | Rationale |
|---|---|---|
| Darwin BPF RX plus measured feth TX API over Network Extension/DriverKit | Network Extension packet tunnel, DriverKit | BPF exposes raw Ethernet capture without an application extension or custom driver. A runtime feth probe measures BPF and `AF_NDRV` TX on the selected kernel before choosing; no third-party historical result is assumed. The shipped path is buffered and copied. |
| Custom transport vs. reusing an existing protocol (QUIC, SCTP) | QUIC, SCTP, raw UDP + manual reliability | The point of the project is the transport internals (SACK/RTO/AIMD) being hand-built and measurable — reusing an existing implementation would remove the thing being demonstrated |
| Pool allocator vs. general-purpose allocator with tuning | `tcmalloc`/`jemalloc` tuning, arena allocators | Hot-path allocation-free is a hard, verifiable claim (zero `malloc` calls) that a tuned general allocator cannot give as cleanly. Instruments counters or labeled wall-clock/throughput proxies evaluate its cost without inventing unavailable HITM data. |
| Explicit RTO/Karn/AIMD per RFC 6298 rather than a simplified timer | Fixed timeout, no Karn's exclusion | A fixed timeout invalidates any latency-under-loss comparison against real TCP, since real TCP doesn't use one; Karn's exclusion specifically matters because the benchmark scenario *is* a loss scenario |
| macOS XNU TCP CUBIC as the sole baseline | Compare against multiple congestion control algorithms | One precisely named, fixed macOS/XNU build and CUBIC baseline keeps the benchmark honest and repeatable; comparing against several would spread effort thin and dilute the core claim |

## 7. Implementation Status And Measurement Policy

The public branch contains the stack code, tests, scripts, and design docs. Raw
local benchmark output is intentionally excluded from the cleaned public history,
because those logs can contain host, interface, UUID, and routing details. Scripts
under `scripts/` reproduce the privileged feth, dummynet, timestamp, and Instruments
checks when run on a compatible Mac.

Implemented and covered by unit or local integration tests:

- Darwin BPF endpoint setup, buffered reads, complete-frame writes, and feth probes.
- Ethernet parsing/building, ARP cache behavior, pending resolution, and refresh.
- IPv4 header parsing, checksum, send-side fragmentation, bounded reassembly,
  duplicate fragments, and first-arrival-wins overlap handling.
- Fixed packet pools and owner-local SPSC handoff rings.
- Transport wire header, connection state machine, retransmission queue,
  receiver SACK generation, sender SACK processing, fast retransmit, RFC 6298 RTO,
  Karn handling, slow start, congestion avoidance, and differentiated loss response.
- Timestamp and histogram plumbing for custom BPF and kernel-TCP diagnostics.

Measurement targets:

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

The link layer owns an explicit runtime spike because public Apple documentation does not
promise which injection API reliably feeds a paired feth interface across every
macOS release. It creates the pair, verifies BPF RX reports `DLT_EN10MB`, attempts a
complete-frame BPF write, attempts an `AF_NDRV` send, and records which frame BPF RX
actually observes. Historical third-party findings are context only. The production
TX path follows the recorded observation from the current OS build.

**Observed selection (2026-07-17 UTC):** on macOS 26.5.1 build 25F80, XNU
25.5.0, and SDK 26.2, BPF RX reported `DLT_EN10MB`. A 60-byte complete frame
written through BPF on `feth0` was captured on `feth1`. A connected `AF_NDRV`
socket also accepted a 60-byte send, but BPF RX captured no matching frame before
the bounded timeout. Therefore this build selects BPF for both RX and TX. This is
not generalized to other macOS builds; rerun the spike after an OS/SDK change.
Local raw evidence is generated under ignored benchmark-artifact directories; packet
captures remain uncommitted because project policy excludes link-layer addresses
from public history.

Default SIP on the selected macOS build leaves `dtruss` with zero syscall rows for
both Apple and third-party binaries. The project uses Instruments System Trace
through `xctrace` for syscall/copy timelines. This is a disclosed tooling
substitution; SIP remains enabled.

On macOS 26.5.1 build 25F80, writing a 10-byte raw frame through BPF into feth
reproducibly triggered a kernel mbuf-validity panic (`len -4`, `rcvif feth1`). Raw
TX therefore rejects frames shorter than the 14-byte Ethernet header before
`write()`. Short/VLAN rejection tests stay in userspace; feth receives valid framing
only. Raw panic reports remain local because they contain machine UUID metadata.

Darwin's public BPF header currently exposes buffered BPF controls but not
`BIOCSETZBUF`, `BIOCROTZBUF`, or `BIOCGETZMAX`. The compile probe on
branch `spike/darwin-bpf-zbuf` confirmed all three absent from selected macOS 26.5
SDK headers, so zbuf promotion is rejected. Main path stays buffered unless a future
supported, measured implementation earns promotion in a later change;
FreeBSD ioctl values are never copied into Darwin code.

### 7.2 Canonical topology and result ownership

The canonical development, correctness, and benchmark topology is a single Mac with
`feth0` peered to `feth1`. Sender and receiver are separate processes bound to
opposite sides. This exercises the complete Ethernet header path; `lo0` is forbidden
for link integration because its `DLT_NULL`/`DLT_LOOP` framing would bypass that
path. `dnctl`/PF rules attach to the two feth interfaces exactly as they would to
physical interfaces.

`bench/report.md` primary numbers come only from feth runs. A later two-Mac Wi-Fi or
ad hoc run is optional and appears only under "cross-host confirmation." Its samples
stay separate because Wi-Fi ARQ changes loss and latency behavior. Meaningful
disagreement must be reported; controlled feth results remain primary rather than
choosing whichever topology looks better. feth does not model a real switch or real
propagation delay, so cross-host confirmation remains useful but never blocking.

## 8. External interfaces

- **Kernel/link**: Darwin BPF RX API, `BIOCSBLEN`, `BIOCSETIF`,
  `BIOCSHDRCMPLT`, `BIOCPROMISC`, `BIOCSSEESENT(0)`, `BIOCIMMEDIATE`, and
  `kqueue`, plus only the feth TX API selected by the runtime feth spike. No
  interaction with the kernel's own IP/TCP stack for custom frames.
- **Timestamping**: BPF capture headers on custom RX, `CLOCK_MONOTONIC` around
  custom TX writes, and `SO_TIMESTAMP_MONOTONIC`/`recvmsg()` control messages for
  kernel-TCP RX. These sources are recorded separately, never presented as equal.
- **Test harness**: dedicated `dnctl` pipes and `pfctl` dummynet rules applied
  symmetrically to `feth0`/`feth1`, with previous state restored after each run.
- **Profiling**: Instruments Counters where supported; otherwise reproducible
  wall-clock/throughput proxy data labeled as such.
- **CI topology**: unit tests need no privilege. Privileged integration jobs create
  a temporary feth pair; no VM or `vmnet.framework` stand-in is required.

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Benchmark numbers get written before being measured | Keep performance claims out of docs unless a reproducible benchmark run backs them and names the baseline |
| ARP-miss stalls masquerade as transport-layer latency | Pending-queue design so ARP resolution never silently drops/delays a segment |
| IP-layer bugs get misattributed to the transport's SACK logic | Reassembly tests isolate overlap, duplicate, timeout, and ordering behavior before transport tests run |
| Unfair baseline comparison | Scripts record feth pair, PF/dummynet settings, payload, duration, trial order, and lack of core pinning |
| feth injection behavior changes across macOS releases | Runtime BPF-vs-`AF_NDRV` spike records observed delivery before selecting a TX API |
| Lock-free allocator/queue introduces subtle races | SPSC handoff stress tests run under TSan-capable builds |

See `LLD.md` for per-module data structures, wire formats, and algorithms.

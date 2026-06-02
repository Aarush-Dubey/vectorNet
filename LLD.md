# Low-Level Design — Userspace Network Stack over macOS BPF

Companion to `HLD.md` (architecture/data-flow) and `AGENTS.md` (phase/commit plan).
This document specifies data structures, wire formats, algorithms, and state
machines per module. Struct layouts are illustrative C++20 — adjust field order
for actual alignment needs, but keep the cache-line claims in `alloc` accurate to
whatever ships.

---

## 1. Link layer (`src/link`)

### 1.1 Darwin feth link channels (buffered baseline)

```cpp
struct BpfChannel {
    int                       fd;              // open /dev/bpf* descriptor
    std::string               interface_name;  // initialization-time storage
    std::unique_ptr<uint8_t[]> read_buffer;    // allocated once before RX starts
    size_t                    buffer_size;     // value negotiated by BIOCSBLEN
    size_t                    bytes_valid;     // bytes returned by current read()
    size_t                    record_offset;   // next bpf_hdr in current buffer
};

enum class TxApi : uint8_t { Bpf, AfNdrv };

struct TxChannel {
    int     fd;
    TxApi   api;  // chosen only from current-kernel Phase-02 spike evidence
};
```

Canonical setup creates `feth0` and `feth1`, peers them with
`ifconfig feth1 peer feth0`, and brings both up. Sender and receiver are separate
processes on opposite sides. `lo0` is never accepted because its
`DLT_NULL`/`DLT_LOOP` records omit the Ethernet framing under test.

Before Phase 02 can select `TxApi`, the spike performs two independent trials on
the current macOS build:

1. Bind BPF RX to `feth1`, require `DLT_EN10MB`, inject one complete marked frame
   through BPF bound to `feth0`, and record write result plus actual delivery.
2. Re-open/flush BPF RX on `feth1`, inject a different marked complete frame through
   an `AF_NDRV` raw socket bound to `feth0`, and record send result plus delivery.

Choose BPF when its frame is observed. Choose `AF_NDRV` only when BPF TX is not
delivered and the `AF_NDRV` frame is observed. A successful syscall without BPF RX
delivery is not success. The evidence records actual UTC time, macOS build, XNU
version, SDK, DLT, syscall results, and delivery results. Re-run after OS upgrades.

Setup order is fixed because Darwin requires the BPF read-buffer size before the
descriptor is attached to an interface:

1. Open the first available `/dev/bpfN`; `EBUSY` means try the next device, while
   permission errors are returned explicitly.
2. Validate BPF major/minor compatibility with `BIOCVERSION`.
3. Request the configured read-buffer size with `BIOCSBLEN`, then retain the size
   returned by the kernel and allocate one userspace buffer of exactly that size.
4. Bind the named interface with `BIOCSETIF`; query `BIOCGDLT` and reject anything
   other than `DLT_EN10MB`.
5. Enable `BIOCSHDRCMPLT` so TX supplies the complete Ethernet header. Apply
   `BIOCPROMISC` only when requested. Set `BIOCSSEESENT` to zero so locally written
   frames are not reflected into RX.
6. Enable `BIOCIMMEDIATE`, flush stale records with `BIOCFLUSH`, register the fd
   with `kqueue`, and only then enter the RX loop.

RX waits for `EVFILT_READ`, then performs one `read()` into the preallocated BPF
buffer. A single read may contain several records:

```text
offset = 0
while offset + sizeof(bpf_hdr) <= bytes_read:
    hdr = buffer + offset
    frame_begin = offset + hdr.bh_hdrlen
    frame_end = frame_begin + hdr.bh_caplen
    reject batch if frame_end exceeds bytes_read
    deliver frame view + hdr.bh_tstamp
    offset += BPF_WORDALIGN(hdr.bh_hdrlen + hdr.bh_caplen)
```

When `TxApi::Bpf` is selected, TX calls one BPF `write()` per complete frame. When
`TxApi::AfNdrv` is selected, TX binds an `AF_NDRV`/`SOCK_RAW` socket to the named
feth interface and calls one `send()` per complete frame. Both remain copied paths;
neither is equivalent to `PACKET_MMAP`/`TPACKET_V3` zero-copy semantics.

Before any Darwin TX syscall, reject raw frames shorter than 14 bytes and frames
larger than `MTU + 14`. Unsupported VLAN construction is rejected in the Ethernet
wrapper. This boundary is mandatory: selected macOS 26.5.1 feth panics in kernel
mbuf validation when given a 10-byte BPF-written frame.

The selected Darwin SDK and public XNU header do not expose `BIOCSETZBUF`,
`BIOCROTZBUF`, or `BIOCGETZMAX`. The post-Phase-03 compile probe on branch
`spike/darwin-bpf-zbuf` confirmed all three absent from macOS 26.5 SDK headers and
rejected zbuf promotion; no runtime probe was attempted. Never define FreeBSD ioctl
values locally. The numbered main path remains buffered until a later phase contains
both support evidence and a committed measurement justifying promotion.

### 1.2 ARP cache

```cpp
struct ArpEntry {
    uint32_t ip;
    MacAddr  mac;
    uint64_t expires_at_ns;
    bool     resolved;
};

struct ArpCache {
    // Fixed-capacity storage allocated during initialization. Phase 05 uses a
    // bounded linear scan because expected peer count is small.
    std::vector<ArpEntry> entries;
    uint64_t ttl_ns; // default 60 seconds
};
```

**Resolve algorithm**:
```
resolve(ip):
    if entries[ip] exists and not expired: return entries[ip].mac
    send ARP request for ip
    return nullopt   // Phase 06 adds in-flight suppression and pending frames

on_arp_reply(ip, mac):
    entries[ip] = { ip, mac, now + TTL, true }
```

Insertion updates an existing address, reuses an empty/expired slot, or returns
`cache_full`; it never grows storage. Phase 06 adds pending-frame storage, request
suppression, and refresh within the fixed five-second margin.

Phase 06 preallocates bounded pending-frame and resolution-state arrays. Each pending
slot holds at most 2,048 bytes. First miss sends one request; later frames for that
target share the in-flight state. Retry interval is 250ms, maximum attempts is three,
and pending deadline is one second. Reply or gratuitous ARP learning flushes every
matching frame in insertion order. Deadline expiry invokes the explicit unreachable
callback and releases all matching slots. Cache entries trigger at most one refresh
sequence when they enter the five-second pre-expiry margin.

---

## 2. Network layer (`src/net`)

### 2.1 IPv4 header

Standard RFC 791 fields (20-byte base header, no options). C++ representation stays
in host order; parser/serializer perform explicit network-byte-order conversion:

```cpp
#pragma pack(push, 1)
struct Ipv4Header {
    uint8_t  version_ihl;      // wire only: version 4, IHL 5
    uint8_t  dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragoffset; // flags:3, fragment offset:13 (units of 8 bytes)
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};
#pragma pack(pop)
static_assert(sizeof(Ipv4Header) == 20);
```

Implementation does not cast packet memory to this struct. It requires version 4 and
IHL 5, verifies total length and header checksum, and trims Ethernet padding using
the IPv4 total-length field. TX defaults are TTL 64 and experimental protocol 253.
The checksum test includes the known header vector whose checksum is `0xb861`.

Flags: bit 0 reserved, bit 1 = DF (unused — this stack always allows
fragmentation), bit 2 = MF (more fragments).

### 2.2 Fragmentation (send side)

```
fragment(payload, mtu):
    max_data_per_frag = (mtu - IP_HEADER_LEN) rounded down to multiple of 8
    offset = 0
    while offset < payload.size():
        chunk = payload[offset : offset + max_data_per_frag]
        more = (offset + chunk.size() < payload.size())
        emit Ipv4Header{ identification = id, flags = more ? MF : 0,
                          frag_offset = offset / 8, ... } + chunk
        offset += chunk.size()
```

Same `identification` value across all fragments of one datagram; sender
increments a per-connection counter for each new datagram.

### 2.3 Reassembly (receive side)

```cpp
struct FragKey { uint32_t src, dst; uint16_t id; uint8_t proto; };  // hashable

struct HoleList {
    // Sorted, non-overlapping list of [start, end) byte ranges not yet received.
    std::vector<std::pair<uint32_t,uint32_t>> holes;
};

struct ReassemblyBuffer {
    std::vector<uint8_t> data;     // sized once total_length is known (last frag)
    HoleList holes;
    uint64_t created_at_ns;
    bool     total_length_known;
};

std::unordered_map<FragKey, ReassemblyBuffer, FragKeyHash> table;
```

**Insert-fragment algorithm** (handles Phase 10's overlap/duplicate case):
```
on_fragment(key, frag_offset, frag_data, more_flag):
    buf = table[key]  // created on first fragment for this key
    end = frag_offset + frag_data.size()
    if not more_flag: buf.total_length_known = true; resize buf.data to end
    // Merge into hole list: remove/shrink any hole segments covered by
    // [frag_offset, end); a fragment overlapping two holes and the gap between
    // them splits into the covered sub-ranges, each processed independently so
    // a partial overlap never double-writes past its own bounds.
    buf.holes.remove_covered(frag_offset, end)
    copy frag_data into buf.data[frag_offset:end]
    if buf.holes.empty() and buf.total_length_known:
        deliver buf.data to net→transport handoff
        table.erase(key)
```

**Timeout sweep** (separate timer thread, per HLD §6): every `SWEEP_INTERVAL`,
scan `table` for entries with `now - created_at_ns > REASSEMBLY_TIMEOUT`, drop
them and release their pooled buffers. `REASSEMBLY_TIMEOUT` is configurable and
should be short (low single-digit seconds) for benchmark runs, not the
kernel-conventional 30–60s.

---

## 3. Pool allocator (`src/alloc`)

### 3.1 Buffer layout

```cpp
struct alignas(64) PacketBuffer {
    uint8_t  data[BUFFER_CAPACITY];   // sized to one MTU-class frame
    uint16_t len;
    // pad to 64-byte multiple implicitly via alignas + capacity choice
};
```

### 3.2 Freelist (single-threaded variant, Phase 11)

```cpp
class Pool {
    std::vector<PacketBuffer> storage;      // fixed, allocated once at init
    std::vector<PacketBuffer*> freelist;    // stack of available buffers
public:
    PacketBuffer* acquire() {
        if (freelist.empty()) return nullptr;  // pool exhaustion is a signal, not silently grown
        auto* b = freelist.back(); freelist.pop_back(); return b;
    }
    void release(PacketBuffer* b) { freelist.push_back(b); }
};
```

### 3.3 Lock-free freelist (Phase 12, cross-thread RX/TX)

Tagged-pointer Treiber stack to avoid ABA:

```cpp
struct alignas(16) TaggedPtr { PacketBuffer* ptr; uint64_t tag; };
std::atomic<TaggedPtr> head;   // requires double-word CAS (DWCAS)

PacketBuffer* acquire() {
    TaggedPtr old = head.load(std::memory_order_acquire);
    TaggedPtr next;
    do {
        if (!old.ptr) return nullptr;
        next = { old.ptr->next_free, old.tag + 1 };
    } while (!head.compare_exchange_weak(old, next, std::memory_order_acq_rel));
    return old.ptr;
}
```

Shared atomic head is padded to its own cache line (`alignas(64)` on the
containing struct) so RX-thread acquires and TX-thread releases don't false-share
with unrelated hot fields.

---

## 4. Transport layer (`src/transport`)

### 4.1 Wire header

```cpp
#pragma pack(push, 1)
struct TransportHeader {
    uint32_t seq;
    uint32_t cumulative_ack;
    uint8_t  flags;          // SYN, ACK, FIN, RST bits
    uint8_t  sack_count;      // 0..MAX_SACK_BLOCKS
    uint16_t window;
    // followed by sack_count * SackBlock, variable length
};
struct SackBlock { uint32_t start; uint32_t end; };
#pragma pack(pop)
```

`MAX_SACK_BLOCKS` fixed (e.g. 4) so the header's max size is known at compile time
for pool-buffer sizing.

### 4.2 Connection state machine

| State | On event | → State |
|---|---|---|
| CLOSED | app calls `connect()` | SYN_SENT (send SYN) |
| CLOSED | receive SYN | SYN_RCVD (send SYN-ACK) |
| SYN_SENT | receive SYN-ACK | ESTABLISHED (send ACK) |
| SYN_RCVD | receive ACK | ESTABLISHED |
| ESTABLISHED | app calls `close()` | FIN_WAIT (send FIN) |
| ESTABLISHED | receive FIN | CLOSE_WAIT (send ACK) |
| FIN_WAIT | receive ACK of FIN | FIN_WAIT2 |
| FIN_WAIT2 | receive FIN | TIME_WAIT (send ACK) |
| CLOSE_WAIT | app calls `close()` | LAST_ACK (send FIN) |
| LAST_ACK | receive ACK | CLOSED |
| TIME_WAIT | timeout (2×MSL-equivalent) | CLOSED |
| any | receive RST | CLOSED (abort, notify app) |

Any transition not listed is invalid and must be rejected (logged, connection
reset) rather than silently ignored — this is what Phase 14's exit criteria
checks.

### 4.3 Retransmission queue (sender)

```cpp
struct PendingSegment {
    uint32_t seq_start, seq_end;
    PacketBuffer* buf;        // pooled, not owned elsewhere
    uint64_t sent_at_ns;
    uint16_t retransmit_count;
    bool     sacked;          // set true when a SACK block covers this range
};
std::map<uint32_t, PendingSegment> queue;  // keyed by seq_start, ordered
```

On cumulative ack advancing past `seq_end`: erase and release buffer.
On a SACK block covering `[seq_start, seq_end)`: mark `sacked = true` but do
**not** erase (still needed if a later cumulative ack hasn't caught up, and for
RTO/Karn accounting) — erase only once cumulative ack passes it.

### 4.4 Receiver out-of-order buffer + SACK generation

```cpp
struct RecvBuffer {
    uint32_t cumulative_ack;   // highest contiguous byte received + 1
    // Sorted set of received-but-not-yet-contiguous ranges:
    std::vector<std::pair<uint32_t,uint32_t>> received_ranges;
};

generate_sack_blocks(buf, max_blocks):
    return first `max_blocks` entries of buf.received_ranges
    // (ordered nearest-to-cumulative_ack first, so the most actionable gaps
    //  are reported first if MAX_SACK_BLOCKS truncates the full set)
```

### 4.5 Sender-side SACK processing → selective retransmit

```
on_ack_received(cumulative_ack, sack_blocks):
    for seg in queue where seg.seq_end <= cumulative_ack:
        release(seg)   // fully acked, in-order
    for block in sack_blocks:
        for seg in queue overlapping block:
            seg.sacked = true
    // Determine holes: any PendingSegment with seq_start < cumulative_ack's
    // "should be acked by now" horizon, not marked sacked, and past RTO or
    // fast-retransmit threshold → retransmit ONLY that segment.
    for seg in queue where not seg.sacked and is_due_for_retransmit(seg):
        retransmit(seg)
```

This is the mechanism distinguishing the design from go-back-N: a single lost
segment triggers exactly one retransmission, not a resend of everything after it.

### 4.6 Fast retransmit

```cpp
uint32_t dup_ack_count = 0;
uint32_t last_ack_seen = 0;

on_ack(ack_seq):
    if ack_seq == last_ack_seen: dup_ack_count++
    else { dup_ack_count = 0; last_ack_seen = ack_seq; }
    if dup_ack_count >= DUP_ACK_THRESHOLD:   // conventionally 3
        retransmit(queue.lowest_unacked_unsacked_segment())
        dup_ack_count = 0
```

### 4.7 RTO estimation (RFC 6298) + Karn's algorithm

```cpp
double srtt = -1, rttvar = 0;   // -1 sentinel = "no sample yet"
const double ALPHA = 1.0/8, BETA = 1.0/4;

on_rtt_sample(measured_rtt_ms, was_retransmitted):
    if was_retransmitted: return   // Karn's algorithm: ambiguous which
                                     // transmission this ACK corresponds to —
                                     // never let it update SRTT/RTTVAR.
    if srtt < 0:
        srtt = measured_rtt_ms; rttvar = measured_rtt_ms / 2;
    else:
        rttvar = (1 - BETA) * rttvar + BETA * abs(srtt - measured_rtt_ms);
        srtt   = (1 - ALPHA) * srtt  + ALPHA * measured_rtt_ms;
    rto = srtt + max(CLOCK_GRANULARITY_MS, 4 * rttvar);
    rto = clamp(rto, RTO_MIN, RTO_MAX);
```

A retransmitted segment's *original* send timestamp must be tagged so
`was_retransmitted` can be checked when its ack (or SACK) eventually arrives.

### 4.8 AIMD congestion control

```cpp
enum class CcState { SLOW_START, CONGESTION_AVOIDANCE };
double cwnd = INITIAL_CWND;       // segments
double ssthresh = INFINITY;
CcState state = CcState::SLOW_START;

on_ack_advances_cumulative():
    if state == SLOW_START:
        cwnd += 1
        if cwnd >= ssthresh: state = CONGESTION_AVOIDANCE
    else:
        cwnd += 1.0 / cwnd    // additive increase, ~1 segment per RTT

on_loss_signal(kind):   // kind = RTO_TIMEOUT | SACK_PARTIAL_LOSS
    // Policy decided in Phase 21 — document whichever is actually implemented:
    ssthresh = cwnd / 2
    if kind == RTO_TIMEOUT:
        cwnd = INITIAL_CWND; state = CcState::SLOW_START
    else:  // SACK_PARTIAL_LOSS — fast-recovery-style, no full reset
        cwnd = ssthresh; state = CcState::CONGESTION_AVOIDANCE
```

**This split must match `src/transport/README.md` exactly** — if the project
only claims "AIMD" without the fast-recovery distinction, implement the simpler
uniform response (both loss kinds behave identically) instead, so the code and
the claim agree.

---

## 5. Instrumentation (`src/instrument`)

```cpp
enum class TimestampSource : uint8_t {
    BPF_RX_CAPTURE,
    LINK_TX_MONOTONIC_BEFORE_SYSCALL,
    LINK_TX_MONOTONIC_AFTER_SYSCALL,
    TCP_RX_MONOTONIC_CMSG,
    APPLICATION_RTT_MONOTONIC,
};

struct Timestamp {
    uint64_t        value_ns;
    TimestampSource source;
};

struct LatencySample {
    Timestamp begin;
    Timestamp end;
};

struct Histogram {
    // Fixed log-linear bucket scheme (e.g. HDR-histogram style) rather than a
    // single running percentile — needed so bench/report.md can show full
    // distribution shape, not just a point estimate.
    std::vector<uint64_t> buckets;
    void record(uint64_t latency_ns);
    uint64_t percentile(double p) const;
    size_t sample_count() const;
};
```

The custom stack has three distinct packet timestamps:

- **RX capture**: `bpf_hdr.bh_tstamp`, assigned by the BPF capture path. Convert
  its Darwin `timeval32` representation carefully and retain the source tag.
- **TX before/after**: `clock_gettime(CLOCK_MONOTONIC)` immediately before and
  after the selected BPF `write()` or `AF_NDRV` `send()`. No kernel-assigned or hardware TX completion timestamp is
  exposed for this path. The interval includes syscall entry/exit overhead.
- **Application RTT**: one process records `CLOCK_MONOTONIC` before a request and
  after its response or acknowledgement. Phase 25 uses this as the primary latency
  comparison so both transports and both feth processes share one monotonic clock.

The kernel-TCP baseline enables `SO_TIMESTAMP_MONOTONIC` on its socket and reads
`SCM_TIMESTAMP_MONOTONIC` from `recvmsg()` control messages. That timestamp is not
used or described as the BPF timestamp source. Packet-level BPF and socket-cmsg
measurements are diagnostic because their capture points differ; the report must
not present them as equal-fidelity one-way latency measurements.

Every raw run records timestamp source, macOS build, chip, feth interfaces/MTU,
dummynet/PF configuration, selected TX API, and whether Instruments exposed the
requested counters. Optional cross-host runs additionally record NICs and remain
separate. No hardware timestamping precision is implied.

---

## 6. Concurrency & memory model summary

- Shared mutable state crossing threads: pool freelist (§3.3), retransmission
  queue (if TX thread and a timer thread both touch it — guard with the same
  lock-free discipline or a single-owner-thread rule, decide explicitly in
  Phase 15/19 and document it).
- Everything else (ARP cache, reassembly table, receive buffer) is owned by a
  single thread (RX) and never touched from TX/timer threads directly — cross-
  thread requests go through a message/queue handoff, not shared mutation.
- No `malloc`/`new` after `Pool` initialization on any data-path thread — verified
  via an interposer or allocation-counting hook in tests, not just code review.

## 7. Edge cases table

| Case | Handling |
|---|---|
| ARP reply never arrives | Pending queue entries are dropped after a bounded wait; caller gets an explicit send failure, not a silent hang |
| Duplicate IP fragment | Interval-merge in §2.3 makes duplicates a no-op past the first copy |
| SACK block count exceeds MAX_SACK_BLOCKS | Truncate to nearest-first (per §4.4); sender will still recover the rest via subsequent acks |
| Pool exhaustion under sustained loss (many unacked segments held) | `acquire()` returns null; caller must apply backpressure (stop admitting new sends) rather than blocking or falling back to `malloc` |
| Reassembly timeout fires mid-copy | Timer sweep only runs between RX-thread processing steps (single-owner-thread rule), so no fragment copy is interrupted |
| RTO fires for a segment that was already SACKed | Check `sacked` flag before retransmitting in the RTO handler, not just in the SACK-processing path |

See `HLD.md` §6 for the rationale behind these boundaries and `AGENTS.md` for
which phase each piece belongs to.

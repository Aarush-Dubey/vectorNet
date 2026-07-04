# Low-Level Design — Userspace Network Stack over macOS BPF

This document is the module-level design for vectorNet. It specifies the concrete
data structures, wire formats, algorithms, state machines, and ownership rules used
by the userspace Ethernet/IPv4/custom-transport stack described in `HLD.md`.
Struct layouts are illustrative C++20; actual code may reorder fields for alignment,
but cache-line and allocation claims must stay true to the shipped implementation.

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
    TxApi   api;  // chosen only from current-kernel feth probe evidence
};
```

Canonical setup creates `feth0` and `feth1`, peers them with
`ifconfig feth1 peer feth0`, and brings both up. Sender and receiver are separate
processes on opposite sides. `lo0` is never accepted because its
`DLT_NULL`/`DLT_LOOP` records omit the Ethernet framing under test.

Before initialization selects `TxApi`, the feth probe performs two independent trials on
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
`BIOCROTZBUF`, or `BIOCGETZMAX`. The compile probe on branch
`spike/darwin-bpf-zbuf` confirmed all three absent from macOS 26.5 SDK headers and
rejected zbuf promotion; no runtime probe was attempted. Never define FreeBSD ioctl
values locally. The main path remains buffered until a later change contains
both support evidence and a reproducible measurement justifying promotion.

### 1.2 ARP cache

```cpp
struct ArpEntry {
    uint32_t ip;
    MacAddr  mac;
    uint64_t expires_at_ns;
    bool     resolved;
};

struct ArpCache {
    // Fixed-capacity storage allocated during initialization. A bounded linear scan
    // is enough because the canonical topology has very few peers.
    std::vector<ArpEntry> entries;
    uint64_t ttl_ns; // default 60 seconds
};
```

**Resolve algorithm**:
```
resolve(ip):
    if entries[ip] exists and not expired: return entries[ip].mac
    send ARP request for ip
    return nullopt   // pending queue handles in-flight suppression and frames

on_arp_reply(ip, mac):
    entries[ip] = { ip, mac, now + TTL, true }
```

Insertion updates an existing address, reuses an empty/expired slot, or returns
`cache_full`; it never grows storage. Pending-frame storage, request suppression,
and refresh logic stay inside fixed-capacity arrays with a five-second refresh
margin.

The ARP layer preallocates bounded pending-frame and resolution-state arrays. Each pending
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
increments a 16-bit per-connection counter for each new datagram, with defined
wraparound. Implementation consumes an input span and caller-owned MTU-sized scratch
buffer. Callback receives each serialized fragment only for callback duration.
Non-final payload sizes are multiples of eight; no heap storage is created by the
fragmentation function.

### 2.3 Reassembly (receive side)

```cpp
struct FragKey { uint32_t src, dst; uint16_t id; uint8_t proto; };  // hashable

struct ReassemblyBuffer {
    std::array<uint8_t, 65515> data;
    std::array<Hole, 8192> holes; // sorted missing [start,end) ranges
    size_t hole_count;
    uint64_t created_at_ns;
    bool     total_length_known;
};

std::array<ReassemblyBuffer, 64> table; // storage allocated during initialization
```

**Insert-fragment algorithm** (first-arrival-wins overlap policy):
```
on_fragment(key, frag_offset, frag_data, more_flag):
    buf = table[key]  // created on first fragment for this key
    end = frag_offset + frag_data.size()
    if not more_flag: buf.total_length_known = true; resize buf.data to end
    // Copy only intersections with current holes. Bytes outside holes arrived
    // earlier and are never overwritten. Then remove/shrink covered holes.
    copy intersections(frag_data, buf.holes) into buf.data
    buf.holes.remove_covered(frag_offset, end)
    count fully-covered fragment as duplicate; count ignored overlap bytes
    if buf.holes.empty() and buf.total_length_known:
        deliver buf.data to net→transport handoff
        table.erase(key)
```

**Timeout sweep** runs from the owner thread's timer path. It scans active slots and
releases entries once `now - created_at_ns >= 5s`. No timer thread exists. Table-full,
malformed, completion, and timeout outcomes have bounded counters.

---

## 3. Pool allocator (`src/alloc`)

### 3.1 Buffer layout

```cpp
struct alignas(64) PacketBuffer {
    std::array<std::byte, 2048> data;
    uint16_t length;
};
static_assert(sizeof(PacketBuffer) % 64 == 0);
```

The default pool allocates 4,096 buffers during initialization. A buffer holds one
MTU-class frame plus headroom. Pool exhaustion returns `nullptr`; it never falls
back to the heap. Invalid and double releases are rejected and counted.

### 3.2 Freelist (single-threaded variant)

```cpp
class Pool {
    std::unique_ptr<PacketBuffer[]> storage; // allocated once at init
    std::unique_ptr<size_t[]> freelist;      // fixed index stack
    std::unique_ptr<uint8_t[]> in_use;       // fixed release validation
    size_t available;
public:
    PacketBuffer* acquire() {
        if (available == 0) return nullptr;
        return &storage[freelist[--available]];
    }
    bool release(PacketBuffer* b) {
        validate ownership and one active acquisition;
        freelist[available++] = index_of(b);
        return true;
    }
};
```

The allocation gate injects a Darwin DYLD interposer for `malloc`, `calloc`,
`realloc`, `free`, scalar/array `new`, and scalar/array `delete`. Gate control and
symbol lookup happen before the hot window. The allocation gate covers 5,120,000
pool operations with zero observed allocation/deallocation calls; this establishes
only the allocation invariant, not a throughput result.

### 3.3 Owner-local pool + bounded SPSC handoff

Packet pools are not concurrently mutated. The owner thread acquires and releases
its buffers. It sends buffer pointers through a bounded SPSC ring; the consumer
returns them through a second bounded SPSC ring:

```cpp
template<class T, size_t Capacity>
struct SpscRing {
    static_assert(std::has_single_bit(Capacity));
    struct alignas(64) Cursor { std::atomic<size_t> value; };
    Cursor producer;
    Cursor consumer;
    alignas(64) std::array<T, Capacity> slots;

    bool try_push(T value); // release-publish after slot write
    bool try_pop(T& value); // acquire-observe before slot read
};
```

Capacity is a power of two; full/empty states return explicit failure. Producer and
consumer cursors occupy separate 64-byte cache lines. This avoids shared freelist
mutation, ABA tags, and 128-bit CAS assumptions. The stress gate runs a
million-transfer handoff/recycle scenario under TSan-capable builds.

---

## 4. Transport layer (`src/transport`)

### 4.1 Wire header

```cpp
struct TransportHeader {
    uint32_t sequence;
    uint32_t cumulative_ack;
    uint8_t  flags;      // SYN=1, ACK=2, FIN=4, RST=8
    uint8_t  sack_count; // 0..4
    uint16_t window;     // available bytes, capped at 65,535
    std::array<SackBlock, 4> sacks;
};
struct SackBlock { uint32_t start; uint32_t end; };
```

The serialized fixed portion is exactly 12 bytes, followed by `sack_count` 8-byte
blocks, for a 44-byte maximum. Multi-byte fields use network byte order. SACK
ranges are half-open `[start,end)` ranges and cannot be empty. Payload starts after
the declared blocks. Normal MSS reserves the worst-case 44-byte transport header
plus the 20-byte IPv4 header, avoiding IP fragmentation in ordinary transport use.

### 4.2 Connection state machine

| State | On event | → State |
|---|---|---|
| CLOSED | app calls `connect()` | SYN_SENT (send SYN) |
| CLOSED | receive SYN | SYN_RCVD (send SYN-ACK) |
| SYN_SENT | receive SYN-ACK | ESTABLISHED (send ACK) |
| SYN_RCVD | receive ACK | ESTABLISHED |
| ESTABLISHED | app calls `close()` | FIN_WAIT (send FIN) |
| ESTABLISHED | receive FIN | CLOSE_WAIT (send ACK) |
| FIN_WAIT_1 | receive ACK of FIN | FIN_WAIT_2 |
| FIN_WAIT_1 | receive FIN | TIME_WAIT (send ACK) |
| FIN_WAIT_2 | receive FIN | TIME_WAIT (send ACK) |
| CLOSE_WAIT | app calls `close()` | LAST_ACK (send FIN) |
| LAST_ACK | receive ACK | CLOSED |
| TIME_WAIT | timeout (2×MSL-equivalent) | CLOSED |
| any | receive RST | CLOSED (abort, notify app) |

Any transition not listed is invalid. It moves to CLOSED, requests at most one RST
for the connection attempt, and emits an application-error action. The state-machine
test covers every state/event pair.

### 4.3 Retransmission queue (sender)

```cpp
struct PendingSegment {
    uint32_t seq_start, seq_end;
    PacketBuffer* buf;        // pooled, not owned elsewhere
    uint64_t sent_at_ns;
    uint16_t retransmit_count;
    bool     sacked;          // set true when a SACK block covers this range
};
std::array<PendingSegment, 1024> queue;
size_t queue_size;
```

Insertion is ordered with modulo-2^32 sequence helpers and rejects duplicate or
backward starts. Distances are constrained by the advertised window to less than
half the sequence space. On cumulative ACK advancing through `sequence_end`, remove
the acknowledged prefix, compact the fixed array, and immediately release every
buffer to its owner pool. Full queues return backpressure; no map or heap node exists.
On a SACK block covering `[seq_start, seq_end)`: mark `sacked = true` but do
**not** erase (still needed if a later cumulative ack hasn't caught up, and for
RTO/Karn accounting) — erase only once cumulative ack passes it.

### 4.4 Receiver out-of-order buffer + SACK generation

```cpp
struct RecvBuffer {
    uint32_t cumulative_ack;   // highest contiguous byte received + 1
    std::array<SackBlock, 1024> received_ranges;
    size_t range_count;
};

generate_sack_blocks(buf, max_blocks):
    return first `max_blocks` entries of buf.received_ranges
    // (ordered nearest-to-cumulative_ack first, so the most actionable gaps
    //  are reported first if MAX_SACK_BLOCKS truncates the full set)
```

Insertion merges adjacent/overlapping half-open ranges. When a range reaches the
cumulative ACK, RX advances through every now-contiguous stored range. Full storage
returns an explicit drop status; no vector grows and ordering uses the sender's
modulo-2^32 helpers.

### 4.5 Sender-side SACK processing → selective retransmit

```
on_ack_received(cumulative_ack, sack_blocks):
    for seg in queue where seg.seq_end <= cumulative_ack:
        release(seg)   // fully acked, in-order
    for block in sack_blocks:
        for seg in queue fully covered by block:
            seg.sacked = true
    // Determine holes: any PendingSegment with seq_start < cumulative_ack's
    // "should be acked by now" horizon, not marked sacked, and past RTO or
    // fast-retransmit threshold → retransmit ONLY that segment.
    for seg in queue where not seg.sacked and is_due_for_retransmit(seg):
        retransmit(seg)
```

This is the mechanism distinguishing the design from go-back-N: a single lost
segment triggers exactly one retransmission, not a resend of everything after it.
Partial SACK overlap never marks a segment delivered; retained records are erased
only by cumulative ACK.

### 4.6 Fast retransmit

```cpp
uint32_t dup_ack_count = 0;
uint32_t last_ack_seen = 0;

on_ack(ack_seq):
    if ack_seq == last_ack_seen: dup_ack_count++
    else { dup_ack_count = 0; last_ack_seen = ack_seq; }
    if dup_ack_count == 3 and not in_recovery:
        retransmit(queue.lowest_unacked_unsacked_segment())
        recovery_point = queue.highest_sequence_end()
        in_recovery = true
    if ack_seq >= recovery_point:
        in_recovery = false
```

The trigger stamps the retransmission time and increments its retransmit count.
Further duplicate ACKs are suppressed inside the same recovery epoch.

### 4.7 RTO estimation (RFC 6298) + Karn's algorithm

```cpp
uint64_t srtt_ns = 0, rttvar_ns = 0;
bool initialized = false;

on_rtt_sample(measured_rtt_ms, was_retransmitted):
    if was_retransmitted: return   // Karn's algorithm: ambiguous which
                                     // transmission this ACK corresponds to —
                                     // never let it update SRTT/RTTVAR.
    if not initialized:
        srtt = sample; rttvar = sample / 2; initialized = true
    else:
        rttvar = (1 - BETA) * rttvar + BETA * abs(srtt - measured_rtt_ms);
        srtt   = (1 - ALPHA) * srtt  + ALPHA * measured_rtt_ms;
    rto = srtt + max(1ms, 4 * rttvar)
    rto = clamp(rto, 1s, 60s)

on_timeout(): rto = min(2 * rto, 60s)
```

A retransmitted segment's *original* send timestamp must be tagged so
`was_retransmitted` can be checked when its ack (or SACK) eventually arrives.
All timestamps use `CLOCK_MONOTONIC`. Initial RTO is one second. Forward progress
clears timeout backoff to the estimator's current computed value.

### 4.8 AIMD congestion control

```cpp
enum class CcState { SLOW_START, CONGESTION_AVOIDANCE };
uint32_t cwnd = 10 * MSS;         // bytes
uint32_t ssthresh = UINT32_MAX;
uint64_t avoidance_acked = 0;
CcState state = CcState::SLOW_START;

on_ack_advances_cumulative(acked_bytes):
    if state == SLOW_START:
        cwnd += acked_bytes
        if cwnd >= ssthresh: state = CONGESTION_AVOIDANCE
    else:
        avoidance_acked += acked_bytes
        when avoidance_acked >= cwnd:
            avoidance_acked -= cwnd
            cwnd += MSS       // one segment per cwnd acknowledged

on_loss_signal(kind):   // kind = RTO_TIMEOUT | SACK_PARTIAL_LOSS
    if already reduced in this recovery epoch: return
    ssthresh = max(flight_bytes / 2, 2 * MSS)
    if kind == RTO_TIMEOUT:
        cwnd = MSS; state = CcState::SLOW_START
    else:  // SACK_PARTIAL_LOSS — fast-recovery-style, no full reset
        cwnd = ssthresh; state = CcState::CONGESTION_AVOIDANCE
    save recovery_point; mark epoch active
```

The actual send limit is `min(cwnd, advertised_window_bytes)`. Flight bytes at or
above that limit return zero send allowance.

An ACK crossing the saved recovery point ends the epoch. Until then, later loss
signals cannot apply another multiplicative decrease.

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
    std::array<uint64_t, 64> buckets;
    uint64_t sample_count;
    uint64_t rejected_samples;
    void record(uint64_t latency_ns);
    uint64_t percentile(double p) const;
    bool write_csv(FILE*, TimestampSource) const;
    bool write_jsonl(FILE*, TimestampSource) const;
};
```

The custom stack has three distinct packet timestamps:

- **RX capture**: `bpf_hdr.bh_tstamp`, assigned by the BPF capture path. Convert
  its Darwin `timeval32` representation carefully and retain the source tag.
- **TX before/after**: `clock_gettime(CLOCK_MONOTONIC)` immediately before and
  after the selected BPF `write()` or `AF_NDRV` `send()`. No kernel-assigned or hardware TX completion timestamp is
  exposed for this path. The interval includes syscall entry/exit overhead.
- **Application RTT**: one process records `CLOCK_MONOTONIC` before a request and
  after its response or acknowledgement. This is the primary latency comparison so
  both transports and both feth processes share one monotonic clock.

The kernel-TCP baseline enables `SO_TIMESTAMP_MONOTONIC` on its socket and reads
`SCM_TIMESTAMP_MONOTONIC` from `recvmsg()` control messages. That timestamp is not
used or described as the BPF timestamp source. Packet-level BPF and socket-cmsg
measurements are diagnostic because their capture points differ; the report must
not present them as equal-fidelity one-way latency measurements.

Every raw run should record timestamp source, macOS build, chip, feth interfaces/MTU,
dummynet/PF configuration, selected TX API, and whether Instruments exposed the
requested counters. Optional cross-host runs additionally record NICs and remain
separate. No hardware timestamping precision is implied.

---

## 6. Concurrency & memory model summary

- Shared mutable state crosses threads only through the bounded SPSC rings in
  §3.3. TX alone owns retransmission, congestion, and RTO state; RX alone owns
  receive ranges and reassembly. Timers are kqueue events in those owner threads.
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

See `HLD.md` §6 for the rationale behind these boundaries.

# vectorNet transport wire format

This is the fixed Phase-13 wire contract. Multi-byte integers use network byte
order. Sequence arithmetic is modulo 2^32; SACK range validation uses wrap-safe
helpers in later phases.

## Fixed header

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | sequence number |
| 4 | 4 | cumulative acknowledgement |
| 8 | 1 | flags |
| 9 | 1 | SACK block count, 0 through 4 |
| 10 | 2 | advertised available bytes, capped at 65,535 |

The fixed header is exactly 12 bytes. Flags are SYN `0x01`, ACK `0x02`, FIN
`0x04`, and RST `0x08`; all other bits are invalid. The header is followed by the
declared number of SACK blocks, so the maximum header size is 44 bytes.

Each SACK block is two 32-bit sequence numbers: `start` then `end`. It describes
the half-open byte range `[start, end)`. Empty ranges are invalid. Phase 16 defines
generation order; Phase 17 defines sender interpretation. Payload begins directly
after the final declared block.

Normal transport MSS is derived from the link MTU minus the 20-byte IPv4 header
and worst-case 44-byte transport header. This prevents normal transport segments
from depending on IPv4 fragmentation.

## Connection transition table

| State | Event | Next state | Wire/application action |
|---|---|---|---|
| CLOSED | app connect | SYN_SENT | send SYN |
| CLOSED | receive SYN | SYN_RECEIVED | send SYN+ACK |
| SYN_SENT | receive SYN | SYN_RECEIVED | send SYN+ACK |
| SYN_SENT | receive SYN+ACK | ESTABLISHED | send ACK; connected |
| SYN_RECEIVED | receive ACK | ESTABLISHED | connected |
| ESTABLISHED | app close | FIN_WAIT_1 | send FIN |
| ESTABLISHED | receive FIN | CLOSE_WAIT | send ACK |
| FIN_WAIT_1 | receive ACK | FIN_WAIT_2 | none |
| FIN_WAIT_1 | receive FIN | TIME_WAIT | send ACK |
| FIN_WAIT_2 | receive FIN | TIME_WAIT | send ACK |
| CLOSE_WAIT | app close | LAST_ACK | send FIN |
| LAST_ACK | receive ACK | CLOSED | closed |
| TIME_WAIT | timeout | CLOSED | closed |
| any non-closed state | receive RST | CLOSED | error; closed |

Undefined pairs are rejected. They close the connection, request one RST at most
for that connection attempt, and emit an application-error action. CLOSED receiving
RST reports error without answering RST; a stale TIME_WAIT timeout in CLOSED is a
no-op.

## Sender retention

The TX owner keeps at most 1,024 `PendingSegment` records in a fixed array ordered
by wrap-safe sequence helpers. Each record owns one pooled buffer until cumulative
ACK processing releases it. ACK processing removes only fully acknowledged prefix
segments and returns their buffers immediately. Queue exhaustion is explicit
backpressure; it never allocates a map node or falls back to heap storage.

## Receiver ranges and SACK generation

The RX owner keeps at most 1,024 sorted, non-overlapping received ranges. Inserts
merge overlap and adjacency. A range beginning at cumulative ACK advances the ACK
and consumes every now-contiguous buffered range. SACK generation copies at most
four stored half-open ranges in nearest-gap-first order. Range-table exhaustion is
an explicit RX drop and never grows storage.

## Sender SACK scoreboard

TX marks a retained segment SACKed only when a reported block fully covers that
segment's half-open range. Partial overlap never marks it. Retransmission selection
walks the fixed queue in sequence order and returns only unsacked records. SACKed
records remain retained for cumulative ACK release and later RTO/Karn accounting.
The Phase-17 fault test loses one middle segment and selects only that hole.

## Fast retransmit

Three duplicate cumulative ACKs trigger retransmission of the lowest unsacked
retained segment. TX records the retransmission time/count and saves the flight's
highest sequence end as the recovery point. Further duplicate ACKs cannot retrigger
inside that epoch; cumulative ACK must cross the recovery point first. This path is
separate from the RTO path added in Phase 19.

## Retransmission timeout

RFC 6298 state uses integer `CLOCK_MONOTONIC` nanoseconds. Initial/minimum RTO is
1 s, maximum is 60 s, and clock granularity is 1 ms. First sample sets SRTT=R and
RTTVAR=R/2; later samples use alpha 1/8 and beta 1/4. Samples from retransmitted
segments are excluded under Karn's rule. Each timeout doubles the active RTO up to
60 s; forward progress clears that backoff to the current computed RTO.

## Congestion growth

Congestion window is tracked in bytes and starts at ten MSS. Slow start adds newly
cumulatively acknowledged bytes, doubling per RTT under one ACK per segment.
Congestion avoidance accumulates acknowledged bytes and adds exactly one MSS after
one cwnd has been acknowledged. The wire send limit is always the smaller of cwnd
and the peer's advertised available-byte window.

## Loss response

Both loss paths set `ssthresh=max(flight/2,2*MSS)`. RTO timeout then sets cwnd to
one MSS and enters slow start. SACK/duplicate-ACK fast loss sets cwnd to ssthresh
and stays in congestion avoidance. TX saves the flight recovery point and permits
only one multiplicative decrease until cumulative ACK crosses it. These trajectories
are intentionally distinct and are tested from identical starting flight state.

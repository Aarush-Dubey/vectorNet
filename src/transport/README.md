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

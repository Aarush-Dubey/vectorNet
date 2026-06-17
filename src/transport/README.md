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

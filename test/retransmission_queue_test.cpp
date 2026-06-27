#include "vectornet/transport/retransmission_queue.hpp"
#include "vectornet/transport/sequence.hpp"

#include <array>
#include <cstdint>
#include <iostream>

namespace {

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

}  // namespace

int main() {
    using namespace vectornet::transport;
    if (!expect(sequence_less(0xFFFFFFF0U, 0x00000010U),
                "wrap-safe less failed") ||
        !expect(sequence_less_equal(0x00000010U, 0x00000010U),
                "wrap-safe equality failed") ||
        !expect(sequence_greater(0x00000020U, 0xFFFFFFF0U),
                "wrap-safe greater failed")) {
        return 1;
    }

    vectornet::alloc::PacketPool pool(3);
    RetransmissionQueue queue(2);
    auto* first = pool.acquire();
    auto* second = pool.acquire();
    auto* spare = pool.acquire();
    if (first == nullptr || second == nullptr || spare == nullptr) {
        return 1;
    }
    if (!expect(queue.enqueue({
                    .sequence_start = 0xFFFFFFF0U,
                    .sequence_end = 0x00000010U,
                    .buffer = first,
                }) == EnqueueStatus::accepted,
                "first enqueue failed") ||
        !expect(queue.enqueue({
                    .sequence_start = 0x00000010U,
                    .sequence_end = 0x00000020U,
                    .buffer = second,
                }) == EnqueueStatus::accepted,
                "second enqueue failed") ||
        !expect(queue.enqueue({
                    .sequence_start = 0x00000020U,
                    .sequence_end = 0x00000030U,
                    .buffer = spare,
                }) == EnqueueStatus::full,
                "full queue accepted a segment")) {
        return 1;
    }
    const auto stale = queue.acknowledge(0xFFFFFFF8U, pool);
    if (!expect(stale.released == 0, "partial ACK released a segment") ||
        !expect(pool.available() == 0, "partial ACK changed pool")) {
        return 1;
    }
    const auto first_ack = queue.acknowledge(0x00000010U, pool);
    if (!expect(first_ack.released == 1 && !first_ack.pool_error,
                "cumulative ACK did not release first segment") ||
        !expect(pool.available() == 1, "ACK did not return buffer immediately") ||
        !expect(queue.size() == 1 && queue.at(0)->buffer == second,
                "queue compaction failed")) {
        return 1;
    }
    if (!expect(pool.release(spare), "spare release failed")) {
        return 1;
    }
    const auto final_ack = queue.acknowledge(0x00000020U, pool);
    if (!expect(final_ack.released == 1, "final ACK release failed") ||
        !expect(queue.empty(), "queue not empty after full ACK") ||
        !expect(pool.available() == pool.capacity(),
                "pool capacity not restored")) {
        return 1;
    }

    vectornet::alloc::PacketPool flight_pool(5);
    RetransmissionQueue flight(5);
    std::array<vectornet::alloc::PacketBuffer*, 5> buffers{};
    for (std::size_t index = 0; index < buffers.size(); ++index) {
        buffers[index] = flight_pool.acquire();
        const std::uint32_t start = 1'000U + static_cast<std::uint32_t>(index) * 100U;
        if (buffers[index] == nullptr ||
            flight.enqueue({
                .sequence_start = start,
                .sequence_end = start + 100U,
                .buffer = buffers[index],
            }) != EnqueueStatus::accepted) {
            return 1;
        }
    }
    const auto prefix = flight.acknowledge(1'200, flight_pool);
    const std::array<SackBlock, 2> sacks{{
        {1'250, 1'350},  // partial coverage must not mark the missing segment
        {1'300, 1'500},  // fully covers only the two received tail segments
    }};
    const auto sack_result = flight.apply_sacks(sacks);
    std::array<PendingSegment*, 5> retransmit{};
    const std::size_t selected = flight.collect_unsacked(retransmit);
    if (!expect(prefix.released == 2, "fault-injection ACK prefix mismatch") ||
        !expect(sack_result.newly_sacked == 2,
                "SACK did not mark exactly received tail segments") ||
        !expect(selected == 1, "selective retransmit chose extra segments") ||
        !expect(retransmit[0]->sequence_start == 1'200 &&
                    retransmit[0]->sequence_end == 1'300,
                "selective retransmit did not choose injected loss")) {
        return 1;
    }
    const auto cleanup = flight.clear(flight_pool);
    return expect(cleanup.released == 3 && !cleanup.pool_error,
                  "selective-flight cleanup failed") &&
                   expect(flight_pool.available() == flight_pool.capacity(),
                          "selective-flight pool leak")
               ? 0
               : 1;
}

#include "vectornet/transport/retransmission_queue.hpp"
#include "vectornet/transport/sequence.hpp"

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
    return expect(final_ack.released == 1, "final ACK release failed") &&
                   expect(queue.empty(), "queue not empty after full ACK") &&
                   expect(pool.available() == pool.capacity(),
                          "pool capacity not restored")
               ? 0
               : 1;
}

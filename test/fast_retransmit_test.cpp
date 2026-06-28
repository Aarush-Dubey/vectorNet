#include "vectornet/transport/fast_retransmit.hpp"

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
    vectornet::alloc::PacketPool pool(3);
    RetransmissionQueue queue(3);
    std::array<vectornet::alloc::PacketBuffer*, 3> buffers{};
    for (std::size_t index = 0; index < buffers.size(); ++index) {
        buffers[index] = pool.acquire();
        const std::uint32_t start = 1'000U + static_cast<std::uint32_t>(index) * 100U;
        if (buffers[index] == nullptr ||
            queue.enqueue({
                .sequence_start = start,
                .sequence_end = start + 100U,
                .buffer = buffers[index],
            }) != EnqueueStatus::accepted) {
            return 1;
        }
    }
    const std::array<SackBlock, 1> tail_sack{{{1'100, 1'300}}};
    if (queue.apply_sacks(tail_sack).newly_sacked != 2) {
        return 1;
    }

    FastRetransmitController controller(1'000);
    if (!expect(!controller.on_ack(1'000, 10'000'000, queue).triggered,
                "triggered on first duplicate ACK") ||
        !expect(!controller.on_ack(1'000, 20'000'000, queue).triggered,
                "triggered on second duplicate ACK")) {
        return 1;
    }
    const auto third = controller.on_ack(1'000, 30'000'000, queue);
    if (!expect(third.triggered, "third duplicate ACK did not trigger") ||
        !expect(third.segment == queue.at(0),
                "fast retransmit did not choose lowest unsacked segment") ||
        !expect(third.segment->retransmit_count == 1,
                "fast retransmit count mismatch") ||
        !expect(third.segment->sent_at_ns == 30'000'000,
                "fast retransmit timestamp mismatch") ||
        !expect(third.segment->sent_at_ns < 1'000'000'000ULL,
                "fast retransmit waited for initial RTO")) {
        return 1;
    }
    for (std::uint64_t time = 40'000'000; time <= 80'000'000; time += 10'000'000) {
        if (!expect(!controller.on_ack(1'000, time, queue).triggered,
                    "recovery epoch emitted repeated fast retransmit")) {
            return 1;
        }
    }
    const auto partial = controller.on_ack(1'100, 90'000'000, queue);
    if (!expect(!partial.recovery_complete && controller.in_recovery(),
                "partial ACK ended recovery epoch")) {
        return 1;
    }
    const auto complete = controller.on_ack(1'300, 100'000'000, queue);
    // `complete` carried the ACK that crossed the saved flight end.
    if (!expect(complete.recovery_complete && !controller.in_recovery(),
                "recovery epoch did not complete")) {
        return 1;
    }
    const auto cleanup = queue.clear(pool);
    return expect(cleanup.released == 3 && pool.available() == pool.capacity(),
                  "fast retransmit fixture leaked buffers")
               ? 0
               : 1;
}

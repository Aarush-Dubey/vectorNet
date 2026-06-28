#include "vectornet/transport/fast_retransmit.hpp"

#include <limits>

#include "vectornet/transport/sequence.hpp"

namespace vectornet::transport {

FastRetransmitController::FastRetransmitController(
    std::uint32_t initial_ack) noexcept
    : last_ack_(initial_ack) {}

FastRetransmitDecision FastRetransmitController::on_ack(
    std::uint32_t cumulative_ack,
    std::uint64_t now_ns,
    RetransmissionQueue& queue) noexcept {
    FastRetransmitDecision decision{};
    if (sequence_greater(cumulative_ack, last_ack_)) {
        last_ack_ = cumulative_ack;
        duplicate_ack_count_ = 0;
        if (in_recovery_ &&
            sequence_less_equal(recovery_point_, cumulative_ack)) {
            in_recovery_ = false;
            decision.recovery_complete = true;
        }
        return decision;
    }
    if (cumulative_ack != last_ack_) {
        return decision;
    }
    if (duplicate_ack_count_ != std::numeric_limits<std::uint32_t>::max()) {
        ++duplicate_ack_count_;
    }
    decision.duplicate_ack_count = duplicate_ack_count_;
    if (duplicate_ack_count_ != kDuplicateAckThreshold || in_recovery_) {
        return decision;
    }
    PendingSegment* segment = queue.lowest_unsacked();
    const PendingSegment* tail = queue.size() == 0 ? nullptr : queue.at(queue.size() - 1);
    if (segment == nullptr || tail == nullptr) {
        return decision;
    }
    if (segment->retransmit_count != std::numeric_limits<std::uint16_t>::max()) {
        ++segment->retransmit_count;
    }
    segment->sent_at_ns = now_ns;
    recovery_point_ = tail->sequence_end;
    in_recovery_ = true;
    decision.segment = segment;
    decision.triggered = true;
    return decision;
}

bool FastRetransmitController::in_recovery() const noexcept {
    return in_recovery_;
}

std::uint32_t FastRetransmitController::duplicate_ack_count() const noexcept {
    return duplicate_ack_count_;
}

}  // namespace vectornet::transport

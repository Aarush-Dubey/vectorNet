#pragma once

#include <cstdint>

#include "vectornet/transport/retransmission_queue.hpp"

namespace vectornet::transport {

inline constexpr std::uint32_t kDuplicateAckThreshold = 3;

struct FastRetransmitDecision {
    PendingSegment* segment{nullptr};
    std::uint32_t duplicate_ack_count{0};
    bool triggered{false};
    bool recovery_complete{false};
};

class FastRetransmitController final {
public:
    explicit FastRetransmitController(std::uint32_t initial_ack) noexcept;

    [[nodiscard]] FastRetransmitDecision on_ack(
        std::uint32_t cumulative_ack,
        std::uint64_t now_ns,
        RetransmissionQueue& queue) noexcept;

    [[nodiscard]] bool in_recovery() const noexcept;
    [[nodiscard]] std::uint32_t duplicate_ack_count() const noexcept;

private:
    std::uint32_t last_ack_{0};
    std::uint32_t recovery_point_{0};
    std::uint32_t duplicate_ack_count_{0};
    bool in_recovery_{false};
};

}  // namespace vectornet::transport

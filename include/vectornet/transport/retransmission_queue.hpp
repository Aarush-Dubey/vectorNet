#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "vectornet/alloc/packet_pool.hpp"
#include "vectornet/transport/wire.hpp"

namespace vectornet::transport {

inline constexpr std::size_t kRetransmissionCapacity = 1'024;

struct PendingSegment {
    std::uint32_t sequence_start{0};
    std::uint32_t sequence_end{0};
    alloc::PacketBuffer* buffer{nullptr};
    std::uint64_t sent_at_ns{0};
    std::uint16_t retransmit_count{0};
    bool sacked{false};
};

enum class EnqueueStatus : std::uint8_t {
    accepted,
    full,
    invalid_segment,
    out_of_order,
};

struct AcknowledgeResult {
    std::size_t released{0};
    bool pool_error{false};
};

struct SackProcessingResult {
    std::size_t newly_sacked{0};
    std::size_t invalid_blocks{0};
};

class RetransmissionQueue final {
public:
    explicit RetransmissionQueue(
        std::size_t capacity = kRetransmissionCapacity) noexcept;

    [[nodiscard]] EnqueueStatus enqueue(const PendingSegment& segment) noexcept;
    [[nodiscard]] AcknowledgeResult acknowledge(
        std::uint32_t cumulative_ack,
        alloc::PacketPool& owner_pool) noexcept;
    [[nodiscard]] AcknowledgeResult clear(alloc::PacketPool& owner_pool) noexcept;
    [[nodiscard]] SackProcessingResult apply_sacks(
        std::span<const SackBlock> sacks) noexcept;
    [[nodiscard]] std::size_t collect_unsacked(
        std::span<PendingSegment*> output) noexcept;
    [[nodiscard]] PendingSegment* lowest_unsacked() noexcept;

    [[nodiscard]] const PendingSegment* at(std::size_t index) const noexcept;
    [[nodiscard]] PendingSegment* at(std::size_t index) noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] std::size_t capacity() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

private:
    std::array<PendingSegment, kRetransmissionCapacity> segments_{};
    std::size_t capacity_{kRetransmissionCapacity};
    std::size_t size_{0};
};

}  // namespace vectornet::transport

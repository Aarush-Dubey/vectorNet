#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "vectornet/transport/wire.hpp"

namespace vectornet::transport {

inline constexpr std::size_t kReceiveRangeCapacity = 1'024;

enum class ReceiveRangeStatus : std::uint8_t {
    accepted,
    duplicate,
    full,
    invalid_range,
    outside_window,
};

struct ReceiveRangeResult {
    ReceiveRangeStatus status{ReceiveRangeStatus::invalid_range};
    std::uint32_t cumulative_ack{0};
    std::uint32_t newly_contiguous_bytes{0};
};

class ReceiveRangeSet final {
public:
    explicit ReceiveRangeSet(
        std::uint32_t initial_sequence,
        std::size_t capacity = kReceiveRangeCapacity) noexcept;

    [[nodiscard]] ReceiveRangeResult insert(
        std::uint32_t start,
        std::uint32_t end) noexcept;
    [[nodiscard]] std::size_t generate_sacks(
        std::span<SackBlock> output) const noexcept;

    [[nodiscard]] std::uint32_t cumulative_ack() const noexcept;
    [[nodiscard]] const SackBlock* at(std::size_t index) const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] std::size_t capacity() const noexcept;

private:
    void remove(std::size_t index) noexcept;
    void advance_contiguous() noexcept;

    std::array<SackBlock, kReceiveRangeCapacity> ranges_{};
    std::size_t capacity_{kReceiveRangeCapacity};
    std::size_t size_{0};
    std::uint32_t cumulative_ack_{0};
};

}  // namespace vectornet::transport

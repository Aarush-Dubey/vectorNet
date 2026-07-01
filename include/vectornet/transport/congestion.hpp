#pragma once

#include <cstdint>
#include <limits>

namespace vectornet::transport {

inline constexpr std::uint32_t kInitialCongestionWindowSegments = 10;

enum class CongestionState : std::uint8_t {
    slow_start,
    congestion_avoidance,
};

enum class LossSignal : std::uint8_t {
    rto_timeout,
    sack_fast_recovery,
};

struct LossResponse {
    std::uint32_t congestion_window_bytes{0};
    std::uint32_t slow_start_threshold_bytes{0};
    CongestionState state{CongestionState::slow_start};
    bool applied{false};
};

class CongestionController final {
public:
    explicit CongestionController(
        std::uint32_t mss_bytes,
        std::uint32_t initial_ssthresh_bytes =
            std::numeric_limits<std::uint32_t>::max()) noexcept;

    void on_ack(std::uint32_t acknowledged_bytes) noexcept;
    [[nodiscard]] LossResponse on_loss(
        LossSignal signal,
        std::uint32_t flight_bytes,
        std::uint32_t recovery_point) noexcept;
    [[nodiscard]] bool on_recovery_ack(std::uint32_t cumulative_ack) noexcept;

    [[nodiscard]] std::uint32_t congestion_window_bytes() const noexcept;
    [[nodiscard]] std::uint32_t slow_start_threshold_bytes() const noexcept;
    [[nodiscard]] CongestionState state() const noexcept;
    [[nodiscard]] bool in_recovery() const noexcept;
    [[nodiscard]] std::uint32_t effective_window_bytes(
        std::uint16_t advertised_window_bytes) const noexcept;
    [[nodiscard]] std::uint32_t send_allowance_bytes(
        std::uint32_t flight_bytes,
        std::uint16_t advertised_window_bytes) const noexcept;

private:
    void add_to_cwnd(std::uint64_t bytes) noexcept;

    std::uint32_t mss_bytes_{1};
    std::uint32_t cwnd_bytes_{kInitialCongestionWindowSegments};
    std::uint32_t ssthresh_bytes_{std::numeric_limits<std::uint32_t>::max()};
    std::uint64_t avoidance_acked_bytes_{0};
    std::uint32_t recovery_point_{0};
    CongestionState state_{CongestionState::slow_start};
    bool in_recovery_{false};
};

}  // namespace vectornet::transport

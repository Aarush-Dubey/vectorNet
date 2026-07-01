#include "vectornet/transport/congestion.hpp"

#include <algorithm>
#include <limits>

namespace vectornet::transport {

CongestionController::CongestionController(
    std::uint32_t mss_bytes,
    std::uint32_t initial_ssthresh_bytes) noexcept
    : mss_bytes_(mss_bytes == 0 ? 1 : mss_bytes),
      ssthresh_bytes_(initial_ssthresh_bytes) {
    const std::uint64_t initial =
        static_cast<std::uint64_t>(mss_bytes_) *
        kInitialCongestionWindowSegments;
    cwnd_bytes_ = static_cast<std::uint32_t>(std::min<std::uint64_t>(
        initial,
        std::numeric_limits<std::uint32_t>::max()));
    if (cwnd_bytes_ >= ssthresh_bytes_) {
        state_ = CongestionState::congestion_avoidance;
    }
}

void CongestionController::on_ack(std::uint32_t acknowledged_bytes) noexcept {
    if (acknowledged_bytes == 0) {
        return;
    }
    if (state_ == CongestionState::slow_start) {
        add_to_cwnd(acknowledged_bytes);
        if (cwnd_bytes_ >= ssthresh_bytes_) {
            state_ = CongestionState::congestion_avoidance;
            avoidance_acked_bytes_ = 0;
        }
        return;
    }
    avoidance_acked_bytes_ += acknowledged_bytes;
    while (avoidance_acked_bytes_ >= cwnd_bytes_) {
        avoidance_acked_bytes_ -= cwnd_bytes_;
        add_to_cwnd(mss_bytes_);
    }
}

std::uint32_t CongestionController::congestion_window_bytes() const noexcept {
    return cwnd_bytes_;
}

std::uint32_t CongestionController::slow_start_threshold_bytes() const noexcept {
    return ssthresh_bytes_;
}

CongestionState CongestionController::state() const noexcept {
    return state_;
}

std::uint32_t CongestionController::effective_window_bytes(
    std::uint16_t advertised_window_bytes) const noexcept {
    return std::min(
        cwnd_bytes_,
        static_cast<std::uint32_t>(advertised_window_bytes));
}

std::uint32_t CongestionController::send_allowance_bytes(
    std::uint32_t flight_bytes,
    std::uint16_t advertised_window_bytes) const noexcept {
    const std::uint32_t limit = effective_window_bytes(advertised_window_bytes);
    return flight_bytes >= limit ? 0 : limit - flight_bytes;
}

void CongestionController::add_to_cwnd(std::uint64_t bytes) noexcept {
    const std::uint64_t expanded = static_cast<std::uint64_t>(cwnd_bytes_) + bytes;
    cwnd_bytes_ = static_cast<std::uint32_t>(std::min<std::uint64_t>(
        expanded,
        std::numeric_limits<std::uint32_t>::max()));
}

}  // namespace vectornet::transport

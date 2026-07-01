#include "vectornet/transport/congestion.hpp"

#include <algorithm>
#include <limits>

#include "vectornet/transport/sequence.hpp"

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

LossResponse CongestionController::on_loss(
    LossSignal signal,
    std::uint32_t flight_bytes,
    std::uint32_t recovery_point) noexcept {
    if (in_recovery_) {
        return {cwnd_bytes_, ssthresh_bytes_, state_, false};
    }
    const std::uint64_t minimum_threshold =
        static_cast<std::uint64_t>(mss_bytes_) * 2U;
    const std::uint64_t halved_flight = flight_bytes / 2U;
    ssthresh_bytes_ = static_cast<std::uint32_t>(std::min<std::uint64_t>(
        std::max(minimum_threshold, halved_flight),
        std::numeric_limits<std::uint32_t>::max()));
    if (signal == LossSignal::rto_timeout) {
        cwnd_bytes_ = mss_bytes_;
        state_ = CongestionState::slow_start;
    } else {
        cwnd_bytes_ = ssthresh_bytes_;
        state_ = CongestionState::congestion_avoidance;
    }
    avoidance_acked_bytes_ = 0;
    recovery_point_ = recovery_point;
    in_recovery_ = true;
    return {cwnd_bytes_, ssthresh_bytes_, state_, true};
}

bool CongestionController::on_recovery_ack(
    std::uint32_t cumulative_ack) noexcept {
    if (!in_recovery_ ||
        !sequence_less_equal(recovery_point_, cumulative_ack)) {
        return false;
    }
    in_recovery_ = false;
    return true;
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

bool CongestionController::in_recovery() const noexcept {
    return in_recovery_;
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

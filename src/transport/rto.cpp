#include "vectornet/transport/rto.hpp"

#include <algorithm>
#include <ctime>

namespace vectornet::transport {

RttSampleStatus RtoEstimator::observe(
    std::uint64_t sent_at_ns,
    std::uint64_t acknowledged_at_ns,
    bool was_retransmitted) noexcept {
    if (acknowledged_at_ns < sent_at_ns) {
        return RttSampleStatus::invalid_timestamp;
    }
    if (was_retransmitted) {
        return RttSampleStatus::karn_excluded;
    }
    const std::uint64_t sample = std::min(
        acknowledged_at_ns - sent_at_ns,
        kMaximumRtoNs);
    if (!initialized_) {
        srtt_ns_ = sample;
        rttvar_ns_ = sample / 2U;
        initialized_ = true;
    } else {
        const std::uint64_t difference = srtt_ns_ > sample
            ? srtt_ns_ - sample
            : sample - srtt_ns_;
        rttvar_ns_ = (3U * rttvar_ns_ + difference) / 4U;
        srtt_ns_ = (7U * srtt_ns_ + sample) / 8U;
    }
    update_computed_rto();
    current_rto_ns_ = computed_rto_ns_;
    return RttSampleStatus::accepted;
}

std::uint64_t RtoEstimator::on_timeout() noexcept {
    current_rto_ns_ = current_rto_ns_ > kMaximumRtoNs / 2U
        ? kMaximumRtoNs
        : current_rto_ns_ * 2U;
    return current_rto_ns_;
}

void RtoEstimator::on_forward_progress() noexcept {
    current_rto_ns_ = computed_rto_ns_;
}

bool RtoEstimator::initialized() const noexcept {
    return initialized_;
}

std::uint64_t RtoEstimator::srtt_ns() const noexcept {
    return srtt_ns_;
}

std::uint64_t RtoEstimator::rttvar_ns() const noexcept {
    return rttvar_ns_;
}

std::uint64_t RtoEstimator::rto_ns() const noexcept {
    return current_rto_ns_;
}

void RtoEstimator::update_computed_rto() noexcept {
    const std::uint64_t variation = std::max(
        kRtoGranularityNs,
        4U * rttvar_ns_);
    const std::uint64_t raw = srtt_ns_ > kMaximumRtoNs - variation
        ? kMaximumRtoNs
        : srtt_ns_ + variation;
    computed_rto_ns_ = std::clamp(raw, kMinimumRtoNs, kMaximumRtoNs);
}

std::uint64_t monotonic_now_ns() noexcept {
    timespec value{};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
        static_cast<std::uint64_t>(value.tv_nsec);
}

}  // namespace vectornet::transport

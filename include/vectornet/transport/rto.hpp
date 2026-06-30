#pragma once

#include <cstdint>

namespace vectornet::transport {

inline constexpr std::uint64_t kRtoGranularityNs = 1'000'000ULL;
inline constexpr std::uint64_t kInitialRtoNs = 1'000'000'000ULL;
inline constexpr std::uint64_t kMinimumRtoNs = 1'000'000'000ULL;
inline constexpr std::uint64_t kMaximumRtoNs = 60'000'000'000ULL;

enum class RttSampleStatus : std::uint8_t {
    accepted,
    karn_excluded,
    invalid_timestamp,
};

class RtoEstimator final {
public:
    [[nodiscard]] RttSampleStatus observe(
        std::uint64_t sent_at_ns,
        std::uint64_t acknowledged_at_ns,
        bool was_retransmitted) noexcept;
    [[nodiscard]] std::uint64_t on_timeout() noexcept;
    void on_forward_progress() noexcept;

    [[nodiscard]] bool initialized() const noexcept;
    [[nodiscard]] std::uint64_t srtt_ns() const noexcept;
    [[nodiscard]] std::uint64_t rttvar_ns() const noexcept;
    [[nodiscard]] std::uint64_t rto_ns() const noexcept;

private:
    void update_computed_rto() noexcept;

    std::uint64_t srtt_ns_{0};
    std::uint64_t rttvar_ns_{0};
    std::uint64_t computed_rto_ns_{kInitialRtoNs};
    std::uint64_t current_rto_ns_{kInitialRtoNs};
    bool initialized_{false};
};

[[nodiscard]] std::uint64_t monotonic_now_ns() noexcept;

}  // namespace vectornet::transport

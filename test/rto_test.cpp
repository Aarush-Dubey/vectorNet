#include "vectornet/transport/rto.hpp"

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
    RtoEstimator estimator;
    if (!expect(estimator.rto_ns() == kInitialRtoNs, "initial RTO mismatch") ||
        !expect(estimator.observe(0, 100'000'000, false) ==
                    RttSampleStatus::accepted,
                "first RTT sample rejected") ||
        !expect(estimator.srtt_ns() == 100'000'000,
                "first SRTT mismatch") ||
        !expect(estimator.rttvar_ns() == 50'000'000,
                "first RTTVAR mismatch") ||
        !expect(estimator.rto_ns() == kMinimumRtoNs,
                "minimum RTO clamp mismatch")) {
        return 1;
    }
    if (!expect(estimator.observe(1'000'000'000, 1'120'000'000, false) ==
                    RttSampleStatus::accepted,
                "second RTT sample rejected") ||
        !expect(estimator.srtt_ns() == 102'500'000,
                "second SRTT mismatch") ||
        !expect(estimator.rttvar_ns() == 42'500'000,
                "second RTTVAR mismatch")) {
        return 1;
    }
    const auto before_karn_srtt = estimator.srtt_ns();
    const auto before_karn_var = estimator.rttvar_ns();
    if (!expect(estimator.observe(2'000'000'000, 2'500'000'000, true) ==
                    RttSampleStatus::karn_excluded,
                "retransmitted RTT sample not excluded") ||
        !expect(estimator.srtt_ns() == before_karn_srtt &&
                    estimator.rttvar_ns() == before_karn_var,
                "Karn-excluded sample changed estimator")) {
        return 1;
    }
    constexpr std::uint64_t expected_backoff[] = {
        2'000'000'000ULL,
        4'000'000'000ULL,
        8'000'000'000ULL,
        16'000'000'000ULL,
        32'000'000'000ULL,
        60'000'000'000ULL,
        60'000'000'000ULL,
    };
    for (const auto expected : expected_backoff) {
        if (!expect(estimator.on_timeout() == expected,
                    "exponential backoff mismatch")) {
            return 1;
        }
    }
    estimator.on_forward_progress();
    if (!expect(estimator.rto_ns() == kMinimumRtoNs,
                "forward progress did not clear timeout backoff") ||
        !expect(estimator.observe(10, 9, false) ==
                    RttSampleStatus::invalid_timestamp,
                "backward timestamp accepted")) {
        return 1;
    }
    const std::uint64_t first = monotonic_now_ns();
    const std::uint64_t second = monotonic_now_ns();
    return expect(first != 0 && second >= first,
                  "CLOCK_MONOTONIC source failed")
               ? 0
               : 1;
}

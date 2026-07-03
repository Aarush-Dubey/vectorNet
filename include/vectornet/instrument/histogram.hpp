#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "vectornet/instrument/timestamp.hpp"

namespace vectornet::instrument {

inline constexpr std::size_t kLatencyHistogramBuckets = 64;

class LatencyHistogram final {
public:
    [[nodiscard]] bool record(std::uint64_t latency_ns) noexcept;
    [[nodiscard]] bool record(
        const Timestamp& begin,
        const Timestamp& end) noexcept;

    [[nodiscard]] std::uint64_t sample_count() const noexcept;
    [[nodiscard]] std::uint64_t rejected_samples() const noexcept;
    [[nodiscard]] std::uint64_t minimum_ns() const noexcept;
    [[nodiscard]] std::uint64_t maximum_ns() const noexcept;
    [[nodiscard]] std::uint64_t percentile(double percentile_value) const noexcept;
    [[nodiscard]] const std::array<std::uint64_t, kLatencyHistogramBuckets>&
    buckets() const noexcept;

    [[nodiscard]] bool write_csv(
        std::FILE* output,
        TimestampSource source) const noexcept;
    [[nodiscard]] bool write_jsonl(
        std::FILE* output,
        TimestampSource source) const noexcept;

private:
    [[nodiscard]] static std::size_t bucket_index(std::uint64_t value_ns) noexcept;
    [[nodiscard]] static std::uint64_t bucket_upper_bound(
        std::size_t index) noexcept;

    std::array<std::uint64_t, kLatencyHistogramBuckets> buckets_{};
    std::uint64_t sample_count_{0};
    std::uint64_t rejected_samples_{0};
    std::uint64_t minimum_ns_{0};
    std::uint64_t maximum_ns_{0};
};

}  // namespace vectornet::instrument

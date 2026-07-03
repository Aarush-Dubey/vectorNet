#include "vectornet/instrument/histogram.hpp"

#include <algorithm>
#include <bit>
#include <limits>

namespace vectornet::instrument {

bool LatencyHistogram::record(std::uint64_t latency_ns) noexcept {
    ++buckets_[bucket_index(latency_ns)];
    if (sample_count_ == 0) {
        minimum_ns_ = latency_ns;
        maximum_ns_ = latency_ns;
    } else {
        minimum_ns_ = std::min(minimum_ns_, latency_ns);
        maximum_ns_ = std::max(maximum_ns_, latency_ns);
    }
    ++sample_count_;
    return true;
}

bool LatencyHistogram::record(
    const Timestamp& begin,
    const Timestamp& end) noexcept {
    const bool same_clock = begin.source == end.source ||
        (begin.source == TimestampSource::link_tx_monotonic_before_syscall &&
         end.source == TimestampSource::link_tx_monotonic_after_syscall);
    if (!same_clock || end.value_ns < begin.value_ns) {
        ++rejected_samples_;
        return false;
    }
    return record(end.value_ns - begin.value_ns);
}

std::uint64_t LatencyHistogram::sample_count() const noexcept {
    return sample_count_;
}

std::uint64_t LatencyHistogram::rejected_samples() const noexcept {
    return rejected_samples_;
}

std::uint64_t LatencyHistogram::minimum_ns() const noexcept {
    return minimum_ns_;
}

std::uint64_t LatencyHistogram::maximum_ns() const noexcept {
    return maximum_ns_;
}

std::uint64_t LatencyHistogram::percentile(double percentile_value) const noexcept {
    if (sample_count_ == 0) {
        return 0;
    }
    const double clamped = std::clamp(percentile_value, 0.0, 100.0);
    const std::uint64_t rank = std::max<std::uint64_t>(
        1,
        static_cast<std::uint64_t>(
            clamped / 100.0 * static_cast<double>(sample_count_) + 0.999999999));
    std::uint64_t cumulative = 0;
    for (std::size_t index = 0; index < buckets_.size(); ++index) {
        cumulative += buckets_[index];
        if (cumulative >= rank) {
            return bucket_upper_bound(index);
        }
    }
    return maximum_ns_;
}

const std::array<std::uint64_t, kLatencyHistogramBuckets>&
LatencyHistogram::buckets() const noexcept {
    return buckets_;
}

bool LatencyHistogram::write_csv(
    std::FILE* output,
    TimestampSource source) const noexcept {
    if (output == nullptr ||
        std::fprintf(output, "source,bucket,upper_bound_ns,count\n") < 0) {
        return false;
    }
    for (std::size_t index = 0; index < buckets_.size(); ++index) {
        if (std::fprintf(
                output,
                "%s,%zu,%llu,%llu\n",
                timestamp_source_name(source),
                index,
                static_cast<unsigned long long>(bucket_upper_bound(index)),
                static_cast<unsigned long long>(buckets_[index])) < 0) {
            return false;
        }
    }
    return true;
}

bool LatencyHistogram::write_jsonl(
    std::FILE* output,
    TimestampSource source) const noexcept {
    if (output == nullptr ||
        std::fprintf(
            output,
            "{\"timestamp_source\":\"%s\",\"sample_count\":%llu,"
            "\"rejected_samples\":%llu,\"minimum_ns\":%llu,"
            "\"maximum_ns\":%llu,\"buckets\":[",
            timestamp_source_name(source),
            static_cast<unsigned long long>(sample_count_),
            static_cast<unsigned long long>(rejected_samples_),
            static_cast<unsigned long long>(minimum_ns_),
            static_cast<unsigned long long>(maximum_ns_)) < 0) {
        return false;
    }
    for (std::size_t index = 0; index < buckets_.size(); ++index) {
        if (std::fprintf(
                output,
                index == 0 ? "%llu" : ",%llu",
                static_cast<unsigned long long>(buckets_[index])) < 0) {
            return false;
        }
    }
    return std::fprintf(output, "]}\n") >= 0;
}

std::size_t LatencyHistogram::bucket_index(std::uint64_t value_ns) noexcept {
    return value_ns == 0
        ? 0
        : static_cast<std::size_t>(std::bit_width(value_ns)) - 1U;
}

std::uint64_t LatencyHistogram::bucket_upper_bound(std::size_t index) noexcept {
    return index >= 63
        ? std::numeric_limits<std::uint64_t>::max()
        : (std::uint64_t{1} << (index + 1U)) - 1U;
}

}  // namespace vectornet::instrument

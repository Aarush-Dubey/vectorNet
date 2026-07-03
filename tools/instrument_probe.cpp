#include "vectornet/instrument/histogram.hpp"
#include "vectornet/instrument/timestamp.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>

namespace {

constexpr std::uint64_t kSamples = 4'096;

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fputs("usage: vectornet_instrument_probe CSV_PATH JSONL_PATH\n", stderr);
        return 2;
    }
    vectornet::instrument::LatencyHistogram histogram;
    for (std::uint64_t index = 0; index < kSamples; ++index) {
        const auto begin = vectornet::instrument::application_timestamp();
        std::atomic_signal_fence(std::memory_order_seq_cst);
        const auto end = vectornet::instrument::application_timestamp();
        if (begin.value_ns == 0 || end.value_ns == 0 ||
            !histogram.record(begin, end)) {
            return 3;
        }
    }
    std::FILE* csv = std::fopen(argv[1], "w");
    std::FILE* jsonl = std::fopen(argv[2], "w");
    if (csv == nullptr || jsonl == nullptr) {
        return 4;
    }
    const bool csv_ok = histogram.write_csv(
        csv,
        vectornet::instrument::TimestampSource::application_rtt_monotonic);
    const bool jsonl_ok = histogram.write_jsonl(
        jsonl,
        vectornet::instrument::TimestampSource::application_rtt_monotonic);
    const bool csv_close_ok = std::fclose(csv) == 0;
    const bool jsonl_close_ok = std::fclose(jsonl) == 0;
    const bool close_ok = csv_close_ok && jsonl_close_ok;
    if (!csv_ok || !jsonl_ok || !close_ok) {
        return 5;
    }
    std::printf(
        "{\"phase\":22,\"gate\":\"clock-path-histogram-self-check\","
        "\"timestamp_source\":\"%s\",\"sample_count\":%llu,"
        "\"bucket_count\":%zu,\"p50_bucket_upper_ns\":%llu,"
        "\"p95_bucket_upper_ns\":%llu,\"p99_bucket_upper_ns\":%llu,"
        "\"status\":\"pass\",\"claim_scope\":"
        "\"instrumentation self-check; not network latency\"}\n",
        vectornet::instrument::timestamp_source_name(
            vectornet::instrument::TimestampSource::application_rtt_monotonic),
        static_cast<unsigned long long>(histogram.sample_count()),
        histogram.buckets().size(),
        static_cast<unsigned long long>(histogram.percentile(50.0)),
        static_cast<unsigned long long>(histogram.percentile(95.0)),
        static_cast<unsigned long long>(histogram.percentile(99.0)));
    return 0;
}

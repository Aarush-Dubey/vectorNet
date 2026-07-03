#include "vectornet/instrument/histogram.hpp"
#include "vectornet/instrument/timestamp.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>

#include <sys/socket.h>
#include <unistd.h>

namespace {

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

}  // namespace

int main() {
    using namespace vectornet::instrument;
    LatencyHistogram histogram;
    for (const std::uint64_t sample : {1ULL, 2ULL, 3ULL, 4ULL, 8ULL, 16ULL}) {
        if (!histogram.record(sample)) {
            return 1;
        }
    }
    if (!expect(histogram.sample_count() == 6, "histogram sample count mismatch") ||
        !expect(histogram.minimum_ns() == 1 && histogram.maximum_ns() == 16,
                "histogram min/max mismatch") ||
        !expect(histogram.percentile(50.0) == 3,
                "histogram p50 bucket mismatch") ||
        !expect(histogram.percentile(100.0) == 31,
                "histogram p100 bucket mismatch") ||
        !expect(histogram.record(
                    link_tx_before_timestamp(100),
                    link_tx_after_timestamp(125)),
                "TX monotonic bracket rejected") ||
        !expect(!histogram.record(
                    bpf_rx_timestamp(100),
                    application_timestamp()),
                "unrelated timestamp domains accepted")) {
        return 1;
    }

    alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(std::uint64_t))>
        control{};
    msghdr message{};
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_TIMESTAMP_MONOTONIC;
    header->cmsg_len = CMSG_LEN(sizeof(std::uint64_t));
    const std::uint64_t cmsg_value = 123'456'789;
    std::memcpy(CMSG_DATA(header), &cmsg_value, sizeof(cmsg_value));
    Timestamp parsed{};
    if (!expect(parse_tcp_monotonic_timestamp(message, parsed),
                "TCP monotonic cmsg not parsed") ||
        !expect(parsed.value_ns == cmsg_value &&
                    parsed.source == TimestampSource::tcp_rx_monotonic_cmsg,
                "TCP monotonic cmsg value/source mismatch")) {
        return 1;
    }

    const int socket_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (!expect(socket_fd >= 0, "UDP socket creation failed")) {
        return 1;
    }
    const std::error_code timestamp_error =
        enable_tcp_monotonic_timestamps(socket_fd);
    ::close(socket_fd);
    if (!expect(!timestamp_error, "SO_TIMESTAMP_MONOTONIC setup failed")) {
        return 1;
    }

    std::FILE* csv = std::tmpfile();
    std::FILE* jsonl = std::tmpfile();
    if (csv == nullptr || jsonl == nullptr ||
        !histogram.write_csv(csv, TimestampSource::application_rtt_monotonic) ||
        !histogram.write_jsonl(jsonl, TimestampSource::application_rtt_monotonic)) {
        return 1;
    }
    std::rewind(jsonl);
    std::array<char, 4'096> text{};
    const std::size_t bytes = std::fread(text.data(), 1, text.size() - 1, jsonl);
    text[bytes] = '\0';
    const bool has_source = std::strstr(
        text.data(), "application CLOCK_MONOTONIC RTT") != nullptr;
    const bool has_count = std::strstr(text.data(), "\"sample_count\":7") != nullptr;
    std::fclose(csv);
    std::fclose(jsonl);
    return expect(has_source && has_count,
                  "JSONL export omitted timestamp source or sample count") &&
                   expect(histogram.buckets().size() == 64,
                          "histogram does not expose all 64 buckets")
               ? 0
               : 1;
}

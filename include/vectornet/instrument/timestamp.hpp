#pragma once

#include <cstdint>
#include <system_error>

#include <sys/socket.h>

namespace vectornet::instrument {

enum class TimestampSource : std::uint8_t {
    bpf_rx_capture,
    link_tx_monotonic_before_syscall,
    link_tx_monotonic_after_syscall,
    tcp_rx_monotonic_cmsg,
    application_rtt_monotonic,
};

struct Timestamp {
    std::uint64_t value_ns{0};
    TimestampSource source{TimestampSource::application_rtt_monotonic};
};

[[nodiscard]] Timestamp bpf_rx_timestamp(std::uint64_t value_ns) noexcept;
[[nodiscard]] Timestamp link_tx_before_timestamp(std::uint64_t value_ns) noexcept;
[[nodiscard]] Timestamp link_tx_after_timestamp(std::uint64_t value_ns) noexcept;
[[nodiscard]] Timestamp application_timestamp() noexcept;

[[nodiscard]] std::error_code enable_tcp_monotonic_timestamps(int socket_fd) noexcept;
[[nodiscard]] bool parse_tcp_monotonic_timestamp(
    const msghdr& message,
    Timestamp& timestamp) noexcept;

[[nodiscard]] const char* timestamp_source_name(TimestampSource source) noexcept;

}  // namespace vectornet::instrument

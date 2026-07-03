#include "vectornet/instrument/timestamp.hpp"

#include <cerrno>
#include <cstring>
#include <ctime>

namespace vectornet::instrument {
namespace {

[[nodiscard]] std::uint64_t monotonic_now_ns() noexcept {
    timespec value{};
    if (::clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
        static_cast<std::uint64_t>(value.tv_nsec);
}

}  // namespace

Timestamp bpf_rx_timestamp(std::uint64_t value_ns) noexcept {
    return {value_ns, TimestampSource::bpf_rx_capture};
}

Timestamp link_tx_before_timestamp(std::uint64_t value_ns) noexcept {
    return {value_ns, TimestampSource::link_tx_monotonic_before_syscall};
}

Timestamp link_tx_after_timestamp(std::uint64_t value_ns) noexcept {
    return {value_ns, TimestampSource::link_tx_monotonic_after_syscall};
}

Timestamp application_timestamp() noexcept {
    return {monotonic_now_ns(), TimestampSource::application_rtt_monotonic};
}

std::error_code enable_tcp_monotonic_timestamps(int socket_fd) noexcept {
    const int enabled = 1;
    if (::setsockopt(
            socket_fd,
            SOL_SOCKET,
            SO_TIMESTAMP_MONOTONIC,
            &enabled,
            sizeof(enabled)) != 0) {
        return {errno, std::generic_category()};
    }
    return {};
}

bool parse_tcp_monotonic_timestamp(
    const msghdr& message,
    Timestamp& timestamp) noexcept {
    msghdr mutable_message = message;
    for (cmsghdr* header = CMSG_FIRSTHDR(&mutable_message);
         header != nullptr;
         header = CMSG_NXTHDR(&mutable_message, header)) {
        if (header->cmsg_level != SOL_SOCKET ||
            header->cmsg_type != SCM_TIMESTAMP_MONOTONIC ||
            header->cmsg_len < CMSG_LEN(sizeof(std::uint64_t))) {
            continue;
        }
        std::uint64_t value = 0;
        std::memcpy(&value, CMSG_DATA(header), sizeof(value));
        timestamp = {value, TimestampSource::tcp_rx_monotonic_cmsg};
        return true;
    }
    return false;
}

const char* timestamp_source_name(TimestampSource source) noexcept {
    switch (source) {
    case TimestampSource::bpf_rx_capture:
        return "bpf_hdr.bh_tstamp";
    case TimestampSource::link_tx_monotonic_before_syscall:
        return "CLOCK_MONOTONIC before link write";
    case TimestampSource::link_tx_monotonic_after_syscall:
        return "CLOCK_MONOTONIC after link write";
    case TimestampSource::tcp_rx_monotonic_cmsg:
        return "SO_TIMESTAMP_MONOTONIC recvmsg cmsg";
    case TimestampSource::application_rtt_monotonic:
        return "application CLOCK_MONOTONIC RTT";
    }
    return "unknown";
}

}  // namespace vectornet::instrument

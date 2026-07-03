#include "vectornet/instrument/histogram.hpp"
#include "vectornet/instrument/timestamp.hpp"
#include "vectornet/net/network_stack.hpp"
#include "vectornet/transport/connection.hpp"

#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

using vectornet::instrument::LatencyHistogram;
using vectornet::instrument::Timestamp;
using vectornet::instrument::TimestampSource;
using vectornet::net::Ipv4Address;
using vectornet::net::NetworkStack;
using vectornet::transport::Connection;
using vectornet::transport::ConnectionError;
using vectornet::transport::ConnectionState;
using vectornet::transport::SendStatus;
using vectornet::transport::TransmitReason;

constexpr std::uint16_t kDefaultTcpPort = 46'000;
constexpr std::uint32_t kClientCustomIp = 0xC6130001U;  // 198.19.0.1
constexpr std::uint32_t kServerCustomIp = 0xC6130002U;  // 198.19.0.2
constexpr std::size_t kMaxPayloadBytes = 1'200;
constexpr std::size_t kRttOutstanding = 32;
constexpr std::uint64_t kNsPerMs = 1'000'000ULL;
constexpr std::uint64_t kNsPerSecond = 1'000'000'000ULL;
constexpr std::array<std::byte, 8> kMagic{
    std::byte{0x56}, std::byte{0x4E}, std::byte{0x42}, std::byte{0x45},
    std::byte{0x4E}, std::byte{0x43}, std::byte{0x48}, std::byte{0x31},
};

enum class Mode : std::uint8_t {
    custom_client,
    custom_server,
    tcp_client,
    tcp_server,
};

enum class Workload : std::uint8_t {
    rtt,
    throughput,
};

struct Options {
    Mode mode{Mode::custom_client};
    Workload workload{Workload::rtt};
    std::string interface_name;
    std::string bind_address{"198.18.0.1"};
    std::string peer_address{"198.18.0.2"};
    Ipv4Address local_custom_ip{kClientCustomIp};
    Ipv4Address peer_custom_ip{kServerCustomIp};
    std::uint16_t tcp_port{kDefaultTcpPort};
    std::uint32_t warmup_ms{1'000};
    std::uint32_t duration_ms{3'000};
    std::uint32_t max_runtime_ms{8'000};
    std::size_t payload_bytes{256};
    std::string output_path;
};

[[nodiscard]] std::uint64_t monotonic_ns() noexcept {
    timespec value{};
    if (::clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0 ||
        value.tv_nsec < 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(value.tv_sec) * kNsPerSecond +
           static_cast<std::uint64_t>(value.tv_nsec);
}

[[nodiscard]] bool parse_u32(std::string_view text, std::uint32_t& value) noexcept {
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end;
}

[[nodiscard]] bool parse_size_value(
    std::string_view text,
    std::size_t& value) noexcept {
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end;
}

[[nodiscard]] bool parse_u16(std::string_view text, std::uint16_t& value) noexcept {
    std::uint32_t parsed = 0;
    if (!parse_u32(text, parsed) || parsed > 65'535U) {
        return false;
    }
    value = static_cast<std::uint16_t>(parsed);
    return true;
}

[[nodiscard]] bool parse_ipv4(std::string_view text, Ipv4Address& value) noexcept {
    in_addr address{};
    const std::string owned(text);
    if (::inet_pton(AF_INET, owned.c_str(), &address) != 1) {
        return false;
    }
    value = ntohl(address.s_addr);
    return true;
}

[[nodiscard]] std::string ipv4_text(Ipv4Address value) {
    in_addr address{.s_addr = htonl(value)};
    char buffer[INET_ADDRSTRLEN]{};
    const char* text = ::inet_ntop(AF_INET, &address, buffer, sizeof(buffer));
    return text == nullptr ? std::string("0.0.0.0") : std::string(text);
}

void write_u64(std::span<std::byte> output, std::size_t offset, std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        const unsigned shift = static_cast<unsigned>((7U - index) * 8U);
        output[offset + index] = static_cast<std::byte>((value >> shift) & 0xFFU);
    }
}

[[nodiscard]] std::uint64_t read_u64(
    std::span<const std::byte> input,
    std::size_t offset) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value = (value << 8U) |
                static_cast<std::uint64_t>(input[offset + index]);
    }
    return value;
}

void fill_payload(
    std::span<std::byte> output,
    std::uint64_t sequence,
    std::uint64_t sent_ns) {
    std::copy(kMagic.begin(), kMagic.end(), output.begin());
    write_u64(output, 8, sequence);
    write_u64(output, 16, sent_ns);
    for (std::size_t index = 24; index < output.size(); ++index) {
        output[index] = static_cast<std::byte>((sequence + index) & 0xFFU);
    }
}

[[nodiscard]] bool valid_payload(std::span<const std::byte> input) noexcept {
    return input.size() >= 24 &&
           std::equal(kMagic.begin(), kMagic.end(), input.begin());
}

[[nodiscard]] const char* mode_name(Mode mode) noexcept {
    switch (mode) {
    case Mode::custom_client:
        return "custom-client";
    case Mode::custom_server:
        return "custom-server";
    case Mode::tcp_client:
        return "tcp-client";
    case Mode::tcp_server:
        return "tcp-server";
    }
    return "unknown";
}

[[nodiscard]] const char* workload_name(Workload workload) noexcept {
    return workload == Workload::rtt ? "rtt" : "throughput";
}

void usage(const char* program) {
    std::cerr
        << "usage: " << program
        << " MODE --workload rtt|throughput --payload-bytes N --warmup-ms N "
           "--duration-ms N --out PATH [mode args]\n"
        << "modes:\n"
        << "  custom-client --interface feth0 --local-custom-ip 198.19.0.1 "
           "--peer-custom-ip 198.19.0.2\n"
        << "  custom-server --interface feth1 --local-custom-ip 198.19.0.2 "
           "--peer-custom-ip 198.19.0.1\n"
        << "  tcp-client --bind 198.18.0.1 --peer 198.18.0.2 --port 46000\n"
        << "  tcp-server --bind 198.18.0.2 --port 46000\n";
}

[[nodiscard]] bool parse_options(int argc, char** argv, Options& options) {
    if (argc < 2) {
        return false;
    }
    const std::string_view mode(argv[1]);
    if (mode == "custom-client") {
        options.mode = Mode::custom_client;
        options.local_custom_ip = kClientCustomIp;
        options.peer_custom_ip = kServerCustomIp;
    } else if (mode == "custom-server") {
        options.mode = Mode::custom_server;
        options.local_custom_ip = kServerCustomIp;
        options.peer_custom_ip = kClientCustomIp;
    } else if (mode == "tcp-client") {
        options.mode = Mode::tcp_client;
    } else if (mode == "tcp-server") {
        options.mode = Mode::tcp_server;
        options.bind_address = "198.18.0.2";
    } else {
        return false;
    }

    for (int index = 2; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--workload" && index + 1 < argc) {
            const std::string_view value(argv[++index]);
            if (value == "rtt") {
                options.workload = Workload::rtt;
            } else if (value == "throughput") {
                options.workload = Workload::throughput;
            } else {
                return false;
            }
        } else if (argument == "--interface" && index + 1 < argc) {
            options.interface_name = argv[++index];
        } else if (argument == "--bind" && index + 1 < argc) {
            options.bind_address = argv[++index];
        } else if (argument == "--peer" && index + 1 < argc) {
            options.peer_address = argv[++index];
        } else if (argument == "--local-custom-ip" && index + 1 < argc) {
            if (!parse_ipv4(argv[++index], options.local_custom_ip)) {
                return false;
            }
        } else if (argument == "--peer-custom-ip" && index + 1 < argc) {
            if (!parse_ipv4(argv[++index], options.peer_custom_ip)) {
                return false;
            }
        } else if (argument == "--port" && index + 1 < argc) {
            if (!parse_u16(argv[++index], options.tcp_port)) {
                return false;
            }
        } else if (argument == "--warmup-ms" && index + 1 < argc) {
            if (!parse_u32(argv[++index], options.warmup_ms)) {
                return false;
            }
        } else if (argument == "--duration-ms" && index + 1 < argc) {
            if (!parse_u32(argv[++index], options.duration_ms)) {
                return false;
            }
        } else if (argument == "--max-runtime-ms" && index + 1 < argc) {
            if (!parse_u32(argv[++index], options.max_runtime_ms)) {
                return false;
            }
        } else if (argument == "--payload-bytes" && index + 1 < argc) {
            if (!parse_size_value(argv[++index], options.payload_bytes)) {
                return false;
            }
        } else if (argument == "--out" && index + 1 < argc) {
            options.output_path = argv[++index];
        } else {
            return false;
        }
    }

    if (options.output_path.empty() || options.payload_bytes < 24 ||
        options.payload_bytes > kMaxPayloadBytes || options.duration_ms == 0) {
        return false;
    }
    const bool custom = options.mode == Mode::custom_client ||
                        options.mode == Mode::custom_server;
    return custom ? !options.interface_name.empty() : true;
}

[[nodiscard]] FILE* open_output(const std::string& path) {
    FILE* file = std::fopen(path.c_str(), "w");
    if (file == nullptr) {
        std::cerr << "open output failed: " << std::strerror(errno) << '\n';
    }
    return file;
}

[[nodiscard]] int close_output(FILE* file) {
    return std::fclose(file) == 0 ? 0 : 1;
}

void print_common_json(FILE* output, const Options& options) {
    std::fprintf(
        output,
        "\"mode\":\"%s\",\"workload\":\"%s\",\"payload_bytes\":%zu,"
        "\"warmup_ms\":%u,\"duration_ms\":%u",
        mode_name(options.mode),
        workload_name(options.workload),
        options.payload_bytes,
        options.warmup_ms,
        options.duration_ms);
}

void print_histogram_json(FILE* output, const LatencyHistogram& histogram) {
    std::fprintf(
        output,
        ",\"rtt_samples\":%llu,\"rtt_min_ns\":%llu,\"rtt_max_ns\":%llu,"
        "\"rtt_p50_upper_ns\":%llu,\"rtt_p95_upper_ns\":%llu,"
        "\"rtt_p99_upper_ns\":%llu",
        static_cast<unsigned long long>(histogram.sample_count()),
        static_cast<unsigned long long>(histogram.minimum_ns()),
        static_cast<unsigned long long>(histogram.maximum_ns()),
        static_cast<unsigned long long>(histogram.percentile(50.0)),
        static_cast<unsigned long long>(histogram.percentile(95.0)),
        static_cast<unsigned long long>(histogram.percentile(99.0)));
}

[[nodiscard]] int set_timeouts(int fd) {
    timeval timeout{.tv_sec = 1, .tv_usec = 0};
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        return 1;
    }
    int one = 1;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
        return 1;
    }
    return 0;
}

[[nodiscard]] bool send_all(int fd, std::span<const std::byte> payload) {
    std::size_t sent = 0;
    while (sent < payload.size()) {
        const ssize_t result = ::send(
            fd,
            payload.data() + sent,
            payload.size() - sent,
            0);
        if (result <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(result);
    }
    return true;
}

[[nodiscard]] bool recv_exact(
    int fd,
    std::span<std::byte> payload,
    bool& timeout,
    bool& timestamp_seen) {
    timeout = false;
    std::size_t received = 0;
    while (received < payload.size()) {
        iovec iov{
            .iov_base = payload.data() + received,
            .iov_len = payload.size() - received,
        };
        std::array<char, 128> control{};
        msghdr message{
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = control.data(),
            .msg_controllen = control.size(),
        };
        const ssize_t result = ::recvmsg(fd, &message, 0);
        if (result < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                timeout = true;
            }
            return false;
        }
        if (result == 0) {
            return false;
        }
        Timestamp timestamp{};
        if (vectornet::instrument::parse_tcp_monotonic_timestamp(
                message, timestamp)) {
            timestamp_seen = true;
        }
        received += static_cast<std::size_t>(result);
    }
    return true;
}

[[nodiscard]] int tcp_connect_socket(const Options& options) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (set_timeouts(fd) != 0 ||
        vectornet::instrument::enable_tcp_monotonic_timestamps(fd)) {
        ::close(fd);
        return -1;
    }

    sockaddr_in bind_address{};
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = 0;
    if (::inet_pton(AF_INET, options.bind_address.c_str(), &bind_address.sin_addr) !=
        1) {
        ::close(fd);
        return -1;
    }
    if (::bind(
            fd,
            reinterpret_cast<sockaddr*>(&bind_address),
            sizeof(bind_address)) != 0) {
        ::close(fd);
        return -1;
    }

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(options.tcp_port);
    if (::inet_pton(AF_INET, options.peer_address.c_str(), &peer.sin_addr) != 1) {
        ::close(fd);
        return -1;
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&peer), sizeof(peer)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

[[nodiscard]] int tcp_listen_socket(const Options& options) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    static_cast<void>(
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
    sockaddr_in bind_address{};
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons(options.tcp_port);
    if (::inet_pton(AF_INET, options.bind_address.c_str(), &bind_address.sin_addr) !=
        1) {
        ::close(fd);
        return -1;
    }
    if (::bind(
            fd,
            reinterpret_cast<sockaddr*>(&bind_address),
            sizeof(bind_address)) != 0 ||
        ::listen(fd, 1) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

[[nodiscard]] int run_tcp_client(const Options& options) {
    FILE* output = open_output(options.output_path);
    if (output == nullptr) {
        return 1;
    }
    const int fd = tcp_connect_socket(options);
    if (fd < 0) {
        std::fprintf(output, "{\"status\":\"fail\",\"reason\":\"tcp_connect\"}\n");
        return close_output(output) == 0 ? 1 : 1;
    }

    std::vector<std::byte> payload(options.payload_bytes);
    LatencyHistogram histogram;
    bool timestamp_seen = false;
    const std::uint64_t connected_ns = monotonic_ns();
    const std::uint64_t warmup_end =
        connected_ns + static_cast<std::uint64_t>(options.warmup_ms) * kNsPerMs;
    const std::uint64_t end_ns =
        warmup_end + static_cast<std::uint64_t>(options.duration_ms) * kNsPerMs;
    std::uint64_t sequence = 0;
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_received = 0;
    std::uint64_t send_failures = 0;
    std::uint64_t receive_failures = 0;

    if (options.workload == Workload::rtt) {
        while (monotonic_ns() < end_ns) {
            std::size_t sent_now = 0;
            const std::uint64_t now = monotonic_ns();
            while (sent_now < kRttOutstanding && now < end_ns) {
                fill_payload(payload, sequence++, monotonic_ns());
                if (!send_all(fd, payload)) {
                    ++send_failures;
                    break;
                }
                bytes_sent += payload.size();
                ++sent_now;
            }
            for (std::size_t index = 0; index < sent_now; ++index) {
                bool timeout = false;
                if (!recv_exact(fd, payload, timeout, timestamp_seen)) {
                    ++receive_failures;
                    if (timeout) {
                        break;
                    }
                    break;
                }
                bytes_received += payload.size();
                const std::uint64_t received_ns = monotonic_ns();
                if (valid_payload(payload) && received_ns >= warmup_end) {
                    const std::uint64_t sent_ns = read_u64(payload, 16);
                    if (sent_ns != 0 && received_ns >= sent_ns) {
                        static_cast<void>(histogram.record(received_ns - sent_ns));
                    }
                }
            }
        }
    } else {
        fill_payload(payload, 0, 0);
        while (monotonic_ns() < end_ns) {
            const std::uint64_t now = monotonic_ns();
            if (!send_all(fd, payload)) {
                ++send_failures;
                break;
            }
            if (now >= warmup_end) {
                bytes_sent += payload.size();
            }
        }
    }
    ::close(fd);
    const double seconds = static_cast<double>(options.duration_ms) / 1000.0;
    const double throughput_bps =
        seconds <= 0.0 ? 0.0 : static_cast<double>(bytes_sent * 8U) / seconds;
    std::fprintf(output, "{");
    print_common_json(output, options);
    std::fprintf(
        output,
        ",\"status\":\"pass\",\"timestamp_source\":\"%s\","
        "\"tcp_rx_timestamp_seen\":%s,\"bytes_sent\":%llu,"
        "\"bytes_received\":%llu,\"send_failures\":%llu,"
        "\"receive_failures\":%llu,\"throughput_bps\":%.3f",
        vectornet::instrument::timestamp_source_name(
            TimestampSource::application_rtt_monotonic),
        timestamp_seen ? "true" : "false",
        static_cast<unsigned long long>(bytes_sent),
        static_cast<unsigned long long>(bytes_received),
        static_cast<unsigned long long>(send_failures),
        static_cast<unsigned long long>(receive_failures),
        throughput_bps);
    print_histogram_json(output, histogram);
    std::fprintf(output, "}\n");
    return close_output(output);
}

[[nodiscard]] int run_tcp_server(const Options& options) {
    FILE* output = open_output(options.output_path);
    if (output == nullptr) {
        return 1;
    }
    const int listen_fd = tcp_listen_socket(options);
    if (listen_fd < 0) {
        std::fprintf(output, "{\"status\":\"fail\",\"reason\":\"tcp_listen\"}\n");
        return close_output(output) == 0 ? 1 : 1;
    }
    const int fd = ::accept(listen_fd, nullptr, nullptr);
    ::close(listen_fd);
    if (fd < 0 || set_timeouts(fd) != 0 ||
        vectornet::instrument::enable_tcp_monotonic_timestamps(fd)) {
        if (fd >= 0) {
            ::close(fd);
        }
        std::fprintf(output, "{\"status\":\"fail\",\"reason\":\"tcp_accept\"}\n");
        return close_output(output) == 0 ? 1 : 1;
    }

    std::vector<std::byte> payload(options.payload_bytes);
    const std::uint64_t start_ns = monotonic_ns();
    const std::uint64_t end_ns =
        start_ns + static_cast<std::uint64_t>(options.max_runtime_ms) * kNsPerMs;
    std::uint64_t bytes_received = 0;
    std::uint64_t bytes_sent = 0;
    std::uint64_t receive_failures = 0;
    bool timestamp_seen = false;
    while (monotonic_ns() < end_ns) {
        bool timeout = false;
        if (!recv_exact(fd, payload, timeout, timestamp_seen)) {
            if (timeout) {
                continue;
            }
            ++receive_failures;
            break;
        }
        bytes_received += payload.size();
        if (options.workload == Workload::rtt) {
            if (!send_all(fd, payload)) {
                break;
            }
            bytes_sent += payload.size();
        }
    }
    ::close(fd);
    std::fprintf(output, "{");
    print_common_json(output, options);
    std::fprintf(
        output,
        ",\"status\":\"pass\",\"timestamp_source\":\"%s\","
        "\"tcp_rx_timestamp_seen\":%s,\"bytes_received\":%llu,"
        "\"bytes_sent\":%llu,\"receive_failures\":%llu}\n",
        vectornet::instrument::timestamp_source_name(
            TimestampSource::tcp_rx_monotonic_cmsg),
        timestamp_seen ? "true" : "false",
        static_cast<unsigned long long>(bytes_received),
        static_cast<unsigned long long>(bytes_sent),
        static_cast<unsigned long long>(receive_failures));
    return close_output(output);
}

struct CustomRuntime {
    const Options* options{nullptr};
    NetworkStack* stack{nullptr};
    Connection* connection{nullptr};
    LatencyHistogram histogram{};
    std::array<std::byte, kMaxPayloadBytes> send_payload{};
    std::array<std::array<std::byte, kMaxPayloadBytes>, 64> pending_echo{};
    std::array<std::size_t, 64> pending_echo_bytes{};
    std::size_t pending_head{0};
    std::size_t pending_tail{0};
    std::size_t pending_count{0};
    std::uint64_t warmup_end_ns{0};
    std::uint64_t end_ns{0};
    std::uint64_t sequence{0};
    std::uint64_t bytes_sent{0};
    std::uint64_t bytes_acked_start{0};
    std::uint64_t bytes_acked_end{0};
    std::uint64_t bytes_received{0};
    std::uint64_t send_failures{0};
    std::uint64_t receive_errors{0};
    std::uint64_t bpf_rx_timestamps{0};
    bool connected{false};
};

[[nodiscard]] std::error_code custom_transmit(
    void* opaque,
    std::span<const std::byte> segment,
    TransmitReason) noexcept {
    auto& runtime = *static_cast<CustomRuntime*>(opaque);
    const auto status = runtime.stack->send_datagram(
        runtime.options->peer_custom_ip, segment, monotonic_ns());
    if (status == vectornet::net::NetworkStatus::accepted ||
        status == vectornet::net::NetworkStatus::queued_for_arp) {
        return {};
    }
    ++runtime.send_failures;
    return std::make_error_code(std::errc::io_error);
}

void custom_error(void* opaque, ConnectionError) noexcept {
    ++static_cast<CustomRuntime*>(opaque)->receive_errors;
}

void custom_state(void* opaque, ConnectionState state) noexcept {
    auto& runtime = *static_cast<CustomRuntime*>(opaque);
    runtime.connected = state == ConnectionState::established;
}

void enqueue_echo(CustomRuntime& runtime, std::span<const std::byte> payload) {
    if (runtime.pending_count >= runtime.pending_echo.size() ||
        payload.size() > kMaxPayloadBytes) {
        ++runtime.receive_errors;
        return;
    }
    auto& slot = runtime.pending_echo[runtime.pending_tail];
    std::copy(payload.begin(), payload.end(), slot.begin());
    runtime.pending_echo_bytes[runtime.pending_tail] = payload.size();
    runtime.pending_tail = (runtime.pending_tail + 1U) % runtime.pending_echo.size();
    ++runtime.pending_count;
}

void custom_receive(void* opaque, std::span<const std::byte> payload) noexcept {
    auto& runtime = *static_cast<CustomRuntime*>(opaque);
    if (runtime.options->workload == Workload::rtt &&
        runtime.options->mode == Mode::custom_server) {
        enqueue_echo(runtime, payload);
        return;
    }
    if (runtime.options->mode == Mode::custom_client &&
        runtime.options->workload == Workload::rtt) {
        const std::uint64_t now = monotonic_ns();
        if (valid_payload(payload) && now >= runtime.warmup_end_ns) {
            const std::uint64_t sent_ns = read_u64(payload, 16);
            if (sent_ns != 0 && now >= sent_ns) {
                static_cast<void>(runtime.histogram.record(now - sent_ns));
            }
        }
    }
    if (monotonic_ns() >= runtime.warmup_end_ns) {
        runtime.bytes_received += payload.size();
    }
}

void custom_datagram(
    void* opaque,
    Ipv4Address,
    std::span<const std::byte> payload,
    const vectornet::link::CaptureMetadata& metadata) noexcept {
    auto& runtime = *static_cast<CustomRuntime*>(opaque);
    if (metadata.capture_timestamp_ns != 0) {
        ++runtime.bpf_rx_timestamps;
    }
    static_cast<void>(runtime.connection->on_segment(payload, monotonic_ns()));
}

void flush_echo(CustomRuntime& runtime) {
    while (runtime.pending_count != 0) {
        const std::size_t index = runtime.pending_head;
        const std::span<const std::byte> payload(
            runtime.pending_echo[index].data(),
            runtime.pending_echo_bytes[index]);
        const SendStatus status = runtime.connection->send(payload, monotonic_ns());
        if (status == SendStatus::would_block) {
            return;
        }
        if (status != SendStatus::accepted) {
            ++runtime.send_failures;
            return;
        }
        runtime.pending_head = (runtime.pending_head + 1U) %
                               runtime.pending_echo.size();
        --runtime.pending_count;
    }
}

void drive_custom_client(CustomRuntime& runtime) {
    if (!runtime.connected) {
        return;
    }
    if (runtime.warmup_end_ns == 0) {
        const std::uint64_t now = monotonic_ns();
        runtime.warmup_end_ns =
            now + static_cast<std::uint64_t>(runtime.options->warmup_ms) * kNsPerMs;
        runtime.end_ns = runtime.warmup_end_ns +
                         static_cast<std::uint64_t>(runtime.options->duration_ms) *
                             kNsPerMs;
    }
    const std::uint64_t now = monotonic_ns();
    if (now >= runtime.end_ns) {
        runtime.bytes_acked_end =
            runtime.connection->statistics().payload_bytes_acked;
        return;
    }
    if (runtime.options->workload == Workload::rtt) {
        for (std::size_t index = 0; index < kRttOutstanding; ++index) {
            fill_payload(
                std::span<std::byte>(
                    runtime.send_payload.data(),
                    runtime.options->payload_bytes),
                runtime.sequence++,
                monotonic_ns());
            const SendStatus status = runtime.connection->send(
                std::span<const std::byte>(
                    runtime.send_payload.data(),
                    runtime.options->payload_bytes),
                monotonic_ns());
            if (status == SendStatus::would_block) {
                return;
            }
            if (status != SendStatus::accepted) {
                ++runtime.send_failures;
                return;
            }
            if (now >= runtime.warmup_end_ns) {
                runtime.bytes_sent += runtime.options->payload_bytes;
            }
        }
    } else {
        fill_payload(
            std::span<std::byte>(
                runtime.send_payload.data(), runtime.options->payload_bytes),
            runtime.sequence++,
            0);
        for (;;) {
            const SendStatus status = runtime.connection->send(
                std::span<const std::byte>(
                    runtime.send_payload.data(),
                    runtime.options->payload_bytes),
                monotonic_ns());
            if (status == SendStatus::would_block) {
                break;
            }
            if (status != SendStatus::accepted) {
                ++runtime.send_failures;
                break;
            }
            if (now >= runtime.warmup_end_ns) {
                runtime.bytes_sent += runtime.options->payload_bytes;
            } else {
                runtime.bytes_acked_start =
                    runtime.connection->statistics().payload_bytes_acked;
            }
        }
    }
}

[[nodiscard]] int run_custom(const Options& options) {
    FILE* output = open_output(options.output_path);
    if (output == nullptr) {
        return 1;
    }
    std::error_code error;
    vectornet::net::NetworkStackConfig stack_config{
        .interface_name = options.interface_name,
        .local_address = options.local_custom_ip,
        .requested_bpf_buffer_bytes = 1U << 20U,
        .promiscuous = false,
    };
    auto stack = NetworkStack::open(stack_config, error);
    if (!stack) {
        std::fprintf(
            output,
            "{\"status\":\"fail\",\"reason\":\"stack_open\",\"error\":\"%s\"}\n",
            error.message().c_str());
        return close_output(output) == 0 ? 1 : 1;
    }

    CustomRuntime runtime{.options = &options, .stack = stack.get()};
    vectornet::transport::ConnectionConfig connection_config{
        .maximum_segment_payload_bytes =
            static_cast<std::uint32_t>(options.payload_bytes),
        .packet_pool_buffers = 4'096,
        .retransmission_capacity = 1'024,
        .receive_capacity = 1'024,
    };
    Connection connection(connection_config, {
        .transmit = &custom_transmit,
        .transmit_context = &runtime,
        .receive = &custom_receive,
        .receive_context = &runtime,
        .state = &custom_state,
        .state_context = &runtime,
        .error = &custom_error,
        .error_context = &runtime,
    });
    runtime.connection = &connection;
    const bool client = options.mode == Mode::custom_client;
    if (client) {
        static_cast<void>(connection.connect(monotonic_ns()));
    }
    const std::uint64_t start_ns = monotonic_ns();
    const std::uint64_t max_end_ns =
        start_ns + static_cast<std::uint64_t>(options.max_runtime_ms) * kNsPerMs;

    while (monotonic_ns() < max_end_ns) {
        const std::error_code poll_error =
            stack->poll_datagrams_for(&custom_datagram, &runtime, 1);
        if (poll_error && poll_error != std::errc::timed_out) {
            ++runtime.receive_errors;
        }
        const std::uint64_t now = monotonic_ns();
        stack->tick(now);
        connection.tick(now);
        if (options.mode == Mode::custom_server) {
            flush_echo(runtime);
        } else {
            drive_custom_client(runtime);
            if (runtime.end_ns != 0 && monotonic_ns() >= runtime.end_ns) {
                break;
            }
        }
    }
    if (options.mode == Mode::custom_client && runtime.bytes_acked_end == 0) {
        runtime.bytes_acked_end = connection.statistics().payload_bytes_acked;
    }
    const auto connection_stats = connection.statistics();
    const auto network_stats = stack->statistics();
    std::error_code bpf_error;
    const auto bpf_stats = stack->bpf_statistics(bpf_error);
    const std::uint64_t acked_delta =
        runtime.bytes_acked_end > runtime.bytes_acked_start
            ? runtime.bytes_acked_end - runtime.bytes_acked_start
            : 0;
    const std::uint64_t throughput_bytes =
        options.workload == Workload::throughput ? acked_delta : runtime.bytes_sent;
    const double seconds = static_cast<double>(options.duration_ms) / 1000.0;
    const double throughput_bps = seconds <= 0.0
        ? 0.0
        : static_cast<double>(throughput_bytes * 8U) / seconds;
    std::fprintf(output, "{");
    print_common_json(output, options);
    std::fprintf(
        output,
        ",\"status\":\"pass\",\"topology\":\"feth0/feth1\","
        "\"custom_local_ip\":\"%s\",\"custom_peer_ip\":\"%s\","
        "\"timestamp_source\":\"%s\",\"bpf_rx_timestamp_samples\":%llu,"
        "\"bytes_sent\":%llu,\"bytes_received\":%llu,"
        "\"payload_bytes_acked\":%llu,\"send_failures\":%llu,"
        "\"receive_errors\":%llu,\"throughput_bps\":%.3f,"
        "\"connection_state\":%u,\"fast_retransmissions\":%llu,"
        "\"rto_retransmissions\":%llu,\"network_ipv4_delivered\":%llu,"
        "\"network_reassembly_drops\":%llu,\"bpf_received\":%u,"
        "\"bpf_dropped\":%u,\"bpf_error\":%s",
        ipv4_text(options.local_custom_ip).c_str(),
        ipv4_text(options.peer_custom_ip).c_str(),
        vectornet::instrument::timestamp_source_name(
            TimestampSource::application_rtt_monotonic),
        static_cast<unsigned long long>(runtime.bpf_rx_timestamps),
        static_cast<unsigned long long>(runtime.bytes_sent),
        static_cast<unsigned long long>(runtime.bytes_received),
        static_cast<unsigned long long>(connection_stats.payload_bytes_acked),
        static_cast<unsigned long long>(runtime.send_failures),
        static_cast<unsigned long long>(runtime.receive_errors),
        throughput_bps,
        static_cast<unsigned int>(connection.state()),
        static_cast<unsigned long long>(connection_stats.fast_retransmissions),
        static_cast<unsigned long long>(connection_stats.rto_retransmissions),
        static_cast<unsigned long long>(network_stats.ipv4_delivered),
        static_cast<unsigned long long>(network_stats.reassembly_drops),
        bpf_stats.received,
        bpf_stats.dropped,
        bpf_error ? "true" : "false");
    print_histogram_json(output, runtime.histogram);
    std::fprintf(output, "}\n");
    return close_output(output);
}

}  // namespace

int main(int argc, char** argv) {
    Options options{};
    if (!parse_options(argc, argv, options)) {
        usage(argv[0]);
        return 64;
    }
    switch (options.mode) {
    case Mode::custom_client:
    case Mode::custom_server:
        return run_custom(options);
    case Mode::tcp_client:
        return run_tcp_client(options);
    case Mode::tcp_server:
        return run_tcp_server(options);
    }
    return 64;
}

#include "vectornet/link/link_endpoint.hpp"

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace {

constexpr std::uint16_t kProbeEtherType = 0x88B5;
constexpr std::size_t kEthernetHeaderBytes = 14;
constexpr std::size_t kMinimumFrameBytes = 60;
constexpr std::size_t kMaximumFrames = 1'000'000;
constexpr std::array<std::byte, 6> kMagic{
    static_cast<std::byte>('V'), static_cast<std::byte>('N'),
    static_cast<std::byte>('E'), static_cast<std::byte>('T'),
    static_cast<std::byte>('B'), static_cast<std::byte>('3'),
};

struct Options {
    std::string_view mode;
    std::string interface_name;
    std::string destination_text;
    std::size_t frames{0};
};

struct RxContext {
    std::size_t frames{0};
    std::uint64_t bytes{0};
    std::uint64_t first_ns{0};
    std::uint64_t last_ns{0};
    bool invalid_metadata{false};
};

[[nodiscard]] std::uint64_t monotonic_ns() noexcept {
    timespec time{};
    if (::clock_gettime(CLOCK_MONOTONIC, &time) != 0 || time.tv_sec < 0 ||
        time.tv_nsec < 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(time.tv_sec) * 1'000'000'000ULL +
           static_cast<std::uint64_t>(time.tv_nsec);
}

void on_frame(
    void* opaque,
    std::span<const std::byte> frame,
    const vectornet::link::CaptureMetadata& metadata) noexcept {
    if (frame.size() < kEthernetHeaderBytes + kMagic.size()) {
        return;
    }
    if (frame[12] != static_cast<std::byte>((kProbeEtherType >> 8U) & 0xFFU) ||
        frame[13] != static_cast<std::byte>(kProbeEtherType & 0xFFU) ||
        std::memcmp(
            frame.data() + kEthernetHeaderBytes,
            kMagic.data(),
            kMagic.size()) != 0) {
        return;
    }

    auto& context = *static_cast<RxContext*>(opaque);
    const std::uint64_t now = monotonic_ns();
    if (context.frames == 0) {
        context.first_ns = now;
    }
    context.last_ns = now;
    ++context.frames;
    context.bytes += frame.size();
    if (metadata.capture_timestamp_ns == 0 ||
        metadata.captured_length != frame.size() ||
        metadata.wire_length < metadata.captured_length) {
        context.invalid_metadata = true;
    }
}

[[nodiscard]] bool parse_size(std::string_view text, std::size_t& value) noexcept {
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end && value > 0 &&
           value <= kMaximumFrames;
}

[[nodiscard]] bool parse_mac(
    std::string_view text,
    std::array<std::uint8_t, 6>& mac) noexcept {
    unsigned int values[6]{};
    int consumed = 0;
    const std::string owned(text);
    const int matched = std::sscanf(
        owned.c_str(),
        "%2x:%2x:%2x:%2x:%2x:%2x%n",
        &values[0],
        &values[1],
        &values[2],
        &values[3],
        &values[4],
        &values[5],
        &consumed);
    if (matched != 6 || consumed != static_cast<int>(text.size())) {
        return false;
    }
    for (std::size_t index = 0; index < mac.size(); ++index) {
        if (values[index] > 0xFFU) {
            return false;
        }
        mac[index] = static_cast<std::uint8_t>(values[index]);
    }
    return true;
}

void usage(std::string_view program) {
    std::cerr << "usage: " << program << " rx --interface IFACE --frames COUNT\n"
              << "       " << program
              << " tx --interface IFACE --destination MAC --frames COUNT\n";
}

[[nodiscard]] bool parse_options(int argc, char** argv, Options& options) {
    if (argc < 6) {
        return false;
    }
    options.mode = argv[1];
    for (int index = 2; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--interface" && index + 1 < argc) {
            options.interface_name = argv[++index];
        } else if (argument == "--destination" && index + 1 < argc) {
            options.destination_text = argv[++index];
        } else if (argument == "--frames" && index + 1 < argc) {
            if (!parse_size(argv[++index], options.frames)) {
                return false;
            }
        } else {
            return false;
        }
    }
    if (options.interface_name.empty() || options.frames == 0) {
        return false;
    }
    if (options.mode == "rx") {
        return options.destination_text.empty();
    }
    return options.mode == "tx" && !options.destination_text.empty();
}

[[nodiscard]] std::unique_ptr<vectornet::link::LinkEndpoint> open_endpoint(
    const std::string& interface_name) {
    vectornet::link::LinkConfig config{
        .interface_name = interface_name,
        .requested_buffer_bytes = 0,
        .promiscuous = false,
    };
    std::error_code error;
    auto endpoint = vectornet::link::LinkEndpoint::open(config, error);
    if (!endpoint) {
        std::cerr << "open failed: " << error.message() << '\n';
    }
    return endpoint;
}

[[nodiscard]] int receive_frames(const Options& options) {
    auto endpoint = open_endpoint(options.interface_name);
    if (!endpoint) {
        return 1;
    }

    RxContext context{};
    std::size_t polls = 0;
    std::size_t max_frames_per_read = 0;
    while (context.frames < options.frames) {
        const std::size_t before = context.frames;
        const std::error_code error = endpoint->poll_frames(&on_frame, &context);
        if (error) {
            std::cerr << "poll failed: " << error.message() << '\n';
            return 1;
        }
        ++polls;
        const std::size_t delivered = context.frames - before;
        if (delivered > max_frames_per_read) {
            max_frames_per_read = delivered;
        }
    }

    std::error_code statistics_error;
    const auto statistics = endpoint->bpf_statistics(statistics_error);
    if (statistics_error || context.invalid_metadata || context.first_ns == 0 ||
        context.last_ns < context.first_ns) {
        std::cerr << "invalid receive evidence\n";
        return 1;
    }
    const std::uint64_t duration_ns = context.last_ns - context.first_ns;
    std::cout << "{\"mode\":\"rx\",\"frames\":" << context.frames
              << ",\"bytes\":" << context.bytes << ",\"poll_calls\":" << polls
              << ",\"max_frames_per_read\":" << max_frames_per_read
              << ",\"duration_ns\":" << duration_ns
              << ",\"bpf_received\":" << statistics.received
              << ",\"bpf_dropped\":" << statistics.dropped << "}\n";
    return 0;
}

[[nodiscard]] int send_frames(const Options& options) {
    std::array<std::uint8_t, 6> destination{};
    if (!parse_mac(options.destination_text, destination)) {
        std::cerr << "invalid destination MAC\n";
        return 64;
    }
    auto endpoint = open_endpoint(options.interface_name);
    if (!endpoint) {
        return 1;
    }

    const auto info = endpoint->interface_info();
    std::array<std::byte, kMinimumFrameBytes> frame{};
    for (std::size_t index = 0; index < destination.size(); ++index) {
        frame[index] = static_cast<std::byte>(destination[index]);
        frame[index + destination.size()] = static_cast<std::byte>(info.mac[index]);
    }
    frame[12] = static_cast<std::byte>((kProbeEtherType >> 8U) & 0xFFU);
    frame[13] = static_cast<std::byte>(kProbeEtherType & 0xFFU);
    std::memcpy(frame.data() + kEthernetHeaderBytes, kMagic.data(), kMagic.size());

    const std::uint64_t start_ns = monotonic_ns();
    for (std::size_t index = 0; index < options.frames; ++index) {
        frame[kEthernetHeaderBytes + kMagic.size()] =
            static_cast<std::byte>(index & 0xFFU);
        const std::error_code error = endpoint->send_frame(frame);
        if (error) {
            std::cerr << "send failed: " << error.message() << '\n';
            return 1;
        }
    }
    const std::uint64_t end_ns = monotonic_ns();
    if (start_ns == 0 || end_ns < start_ns) {
        std::cerr << "invalid monotonic clock\n";
        return 1;
    }
    std::cout << "{\"mode\":\"tx\",\"frames\":" << options.frames
              << ",\"bytes\":" << options.frames * frame.size()
              << ",\"duration_ns\":" << end_ns - start_ns << "}\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    Options options{};
    if (!parse_options(argc, argv, options)) {
        usage(argv[0]);
        return 64;
    }
    return options.mode == "rx" ? receive_frames(options) : send_frames(options);
}

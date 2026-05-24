#include "vectornet/link/ethernet.hpp"

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace {

using vectornet::link::EthernetEndpoint;
using vectornet::link::EthernetHeader;
using vectornet::link::MacAddress;

constexpr std::size_t kIpv4Bytes = 20;
constexpr std::array<std::byte, 8> kMagic{
    std::byte{'V'}, std::byte{'N'}, std::byte{'E'}, std::byte{'T'},
    std::byte{'P'}, std::byte{'0'}, std::byte{'4'}, std::byte{'!'},
};

struct Options {
    std::string_view mode;
    std::string interface_name;
    std::string destination_text;
};

struct ServerContext {
    EthernetEndpoint* endpoint{nullptr};
    bool request_received{false};
    bool valid_request{false};
    std::error_code send_error{};
};

struct ClientContext {
    bool response_received{false};
    bool valid_response{false};
};

[[nodiscard]] bool parse_mac(std::string_view text, MacAddress& mac) noexcept {
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

[[nodiscard]] std::array<std::byte, kIpv4Bytes> make_payload() noexcept {
    std::array<std::byte, kIpv4Bytes> payload{};
    payload[0] = std::byte{0x45};
    payload[2] = std::byte{0x00};
    payload[3] = std::byte{static_cast<unsigned char>(kIpv4Bytes)};
    payload[8] = std::byte{64};
    payload[9] = std::byte{253};
    std::memcpy(payload.data() + 12, kMagic.data(), kMagic.size());
    return payload;
}

[[nodiscard]] bool valid_payload(std::span<const std::byte> payload) noexcept {
    return payload.size() >= kIpv4Bytes && payload[0] == std::byte{0x45} &&
           payload[2] == std::byte{0x00} &&
           payload[3] == std::byte{static_cast<unsigned char>(kIpv4Bytes)} &&
           payload[9] == std::byte{253} &&
           std::memcmp(payload.data() + 12, kMagic.data(), kMagic.size()) == 0;
}

void on_server_frame(
    void* opaque,
    const EthernetHeader& header,
    std::span<const std::byte> payload,
    const vectornet::link::CaptureMetadata&) noexcept {
    auto& context = *static_cast<ServerContext*>(opaque);
    if (header.ether_type != vectornet::link::kEtherTypeIpv4 ||
        !valid_payload(payload)) {
        return;
    }
    context.request_received = true;
    context.valid_request = true;
    context.send_error = context.endpoint->send_frame(
        header.source,
        vectornet::link::kEtherTypeIpv4,
        payload.first(kIpv4Bytes));
}

void on_client_frame(
    void* opaque,
    const EthernetHeader& header,
    std::span<const std::byte> payload,
    const vectornet::link::CaptureMetadata&) noexcept {
    auto& context = *static_cast<ClientContext*>(opaque);
    if (header.ether_type == vectornet::link::kEtherTypeIpv4 && valid_payload(payload)) {
        context.response_received = true;
        context.valid_response = true;
    }
}

[[nodiscard]] std::unique_ptr<EthernetEndpoint> open_ethernet(
    const std::string& interface_name) {
    vectornet::link::LinkConfig config{
        .interface_name = interface_name,
        .requested_buffer_bytes = 0,
        .promiscuous = false,
    };
    std::error_code error;
    auto endpoint = EthernetEndpoint::open(config, error);
    if (!endpoint) {
        std::cerr << "Ethernet open failed: " << error.message() << '\n';
    }
    return endpoint;
}

[[nodiscard]] std::unique_ptr<vectornet::link::LinkEndpoint> open_raw(
    const std::string& interface_name) {
    vectornet::link::LinkConfig config{
        .interface_name = interface_name,
        .requested_buffer_bytes = 0,
        .promiscuous = false,
    };
    std::error_code error;
    auto endpoint = vectornet::link::LinkEndpoint::open(config, error);
    if (!endpoint) {
        std::cerr << "raw open failed: " << error.message() << '\n';
    }
    return endpoint;
}

[[nodiscard]] int run_server(const Options& options) {
    auto endpoint = open_ethernet(options.interface_name);
    if (!endpoint) {
        return 1;
    }
    ServerContext context{.endpoint = endpoint.get()};
    while (!context.request_received) {
        const std::error_code error = endpoint->poll_frames(&on_server_frame, &context);
        if (error) {
            std::cerr << "poll failed: " << error.message() << '\n';
            return 1;
        }
    }
    const auto drops = endpoint->drop_counters();
    std::error_code statistics_error;
    const auto statistics = endpoint->bpf_statistics(statistics_error);
    const bool passed = context.valid_request && !context.send_error &&
                        !statistics_error && drops.short_frames == 0 &&
                        drops.vlan_frames == 0;
    std::cout << "{\"mode\":\"server\",\"valid_request\":"
              << (context.valid_request ? "true" : "false")
              << ",\"response_sent\":" << (!context.send_error ? "true" : "false")
              << ",\"parser_short_drops\":" << drops.short_frames
              << ",\"parser_vlan_drops\":" << drops.vlan_frames
              << ",\"bpf_received\":" << statistics.received
              << ",\"bpf_dropped\":" << statistics.dropped
              << ",\"status\":\"" << (passed ? "pass" : "fail") << "\"}\n";
    return passed ? 0 : 1;
}

[[nodiscard]] int run_client(const Options& options) {
    MacAddress destination{};
    if (!parse_mac(options.destination_text, destination)) {
        std::cerr << "invalid destination MAC\n";
        return 64;
    }
    auto endpoint = open_ethernet(options.interface_name);
    auto raw = open_raw(options.interface_name);
    if (!endpoint || !raw) {
        return 1;
    }
    const auto payload = make_payload();
    std::array<std::byte, 10> short_frame{};
    const std::error_code short_error = raw->send_frame(short_frame);
    if (!short_error) {
        std::cerr << "short frame reached BPF TX\n";
        return 1;
    }
    const std::error_code vlan_error = endpoint->send_frame(
        destination,
        vectornet::link::kEtherTypeVlan8021Q,
        payload);
    if (!vlan_error) {
        std::cerr << "VLAN frame reached BPF TX\n";
        return 1;
    }

    const std::error_code send_error = endpoint->send_frame(
        destination,
        vectornet::link::kEtherTypeIpv4,
        payload);
    if (send_error) {
        std::cerr << "valid send failed: " << send_error.message() << '\n';
        return 1;
    }

    ClientContext context{};
    while (!context.response_received) {
        const std::error_code error = endpoint->poll_frames(&on_client_frame, &context);
        if (error) {
            std::cerr << "poll failed: " << error.message() << '\n';
            return 1;
        }
    }
    const auto drops = endpoint->drop_counters();
    const bool passed = context.valid_response && short_error && vlan_error &&
                        drops.short_frames == 0 && drops.vlan_frames == 0;
    std::cout << "{\"mode\":\"client\",\"short_rejected_before_kernel\":true"
              << ",\"short_rejection_errno\":" << short_error.value()
              << ",\"vlan_rejected_before_kernel\":true"
              << ",\"vlan_rejection_errno\":" << vlan_error.value()
              << ",\"valid_response\":"
              << (context.valid_response ? "true" : "false")
              << ",\"parser_short_drops\":" << drops.short_frames
              << ",\"parser_vlan_drops\":" << drops.vlan_frames
              << ",\"status\":\"" << (passed ? "pass" : "fail") << "\"}\n";
    return passed ? 0 : 1;
}

void usage(std::string_view program) {
    std::cerr << "usage: " << program << " server --interface IFACE\n"
              << "       " << program
              << " client --interface IFACE --destination MAC\n";
}

[[nodiscard]] bool parse_options(int argc, char** argv, Options& options) {
    if (argc < 4) {
        return false;
    }
    options.mode = argv[1];
    for (int index = 2; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--interface" && index + 1 < argc) {
            options.interface_name = argv[++index];
        } else if (argument == "--destination" && index + 1 < argc) {
            options.destination_text = argv[++index];
        } else {
            return false;
        }
    }
    if (options.interface_name.empty()) {
        return false;
    }
    return options.mode == "server"
        ? options.destination_text.empty()
        : options.mode == "client" && !options.destination_text.empty();
}

}  // namespace

int main(int argc, char** argv) {
    Options options{};
    if (!parse_options(argc, argv, options)) {
        usage(argv[0]);
        return 64;
    }
    return options.mode == "server" ? run_server(options) : run_client(options);
}

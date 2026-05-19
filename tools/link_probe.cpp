#include "vectornet/link/link_endpoint.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace {

constexpr std::uint16_t kProbeEtherType = 0x88B5;
constexpr std::size_t kEthernetHeaderBytes = 14;
constexpr std::size_t kMinimumFrameBytes = 60;

void print_usage(std::string_view program) {
    std::cerr << "usage: " << program << " info --interface IFACE [--mac-only]\n"
              << "       " << program
              << " send --interface IFACE --destination XX:XX:XX:XX:XX:XX\n";
}

[[nodiscard]] bool parse_mac(
    std::string_view text,
    std::array<std::uint8_t, 6>& mac) noexcept {
    unsigned int values[6]{};
    int consumed = 0;
    const int matched = std::sscanf(
        std::string(text).c_str(),
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

void print_mac(const std::array<std::uint8_t, 6>& mac) {
    std::printf(
        "%02x:%02x:%02x:%02x:%02x:%02x\n",
        static_cast<unsigned int>(mac[0]),
        static_cast<unsigned int>(mac[1]),
        static_cast<unsigned int>(mac[2]),
        static_cast<unsigned int>(mac[3]),
        static_cast<unsigned int>(mac[4]),
        static_cast<unsigned int>(mac[5]));
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

}  // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        print_usage(argv[0]);
        return 64;
    }

    const std::string_view mode = argv[1];
    std::string interface_name;
    std::string destination_text;
    bool mac_only = false;

    for (int index = 2; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (argument == "--interface" && index + 1 < argc) {
            interface_name = argv[++index];
        } else if (argument == "--destination" && index + 1 < argc) {
            destination_text = argv[++index];
        } else if (argument == "--mac-only") {
            mac_only = true;
        } else {
            print_usage(argv[0]);
            return 64;
        }
    }

    if (interface_name.empty()) {
        print_usage(argv[0]);
        return 64;
    }

    auto endpoint = open_endpoint(interface_name);
    if (!endpoint) {
        return 1;
    }
    const vectornet::link::InterfaceInfo info = endpoint->interface_info();

    if (mode == "info") {
        if (!destination_text.empty()) {
            print_usage(argv[0]);
            return 64;
        }
        if (mac_only) {
            print_mac(info.mac);
        } else {
            std::cout << "{\"status\":\"ready\",\"mtu\":" << info.mtu
                      << ",\"bpf_buffer_bytes\":" << info.bpf_buffer_bytes << "}\n";
        }
        return 0;
    }

    if (mode != "send" || destination_text.empty() || mac_only) {
        print_usage(argv[0]);
        return 64;
    }

    std::array<std::uint8_t, 6> destination{};
    if (!parse_mac(destination_text, destination)) {
        std::cerr << "invalid destination MAC\n";
        return 64;
    }

    std::array<std::byte, kMinimumFrameBytes> frame{};
    for (std::size_t index = 0; index < destination.size(); ++index) {
        frame[index] = static_cast<std::byte>(destination[index]);
        frame[index + destination.size()] = static_cast<std::byte>(info.mac[index]);
    }
    frame[12] = static_cast<std::byte>((kProbeEtherType >> 8U) & 0xFFU);
    frame[13] = static_cast<std::byte>(kProbeEtherType & 0xFFU);
    constexpr std::array<std::byte, 6> magic{
        static_cast<std::byte>('V'), static_cast<std::byte>('N'),
        static_cast<std::byte>('E'), static_cast<std::byte>('T'),
        static_cast<std::byte>('P'), static_cast<std::byte>('2'),
    };
    std::memcpy(frame.data() + kEthernetHeaderBytes, magic.data(), magic.size());

    const std::error_code error = endpoint->send_frame(frame);
    if (error) {
        std::cerr << "send failed: " << error.message() << '\n';
        return 1;
    }

    std::cout << "{\"status\":\"sent\",\"bytes\":" << frame.size() << "}\n";
    return 0;
}

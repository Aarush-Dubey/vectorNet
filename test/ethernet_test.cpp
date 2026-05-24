#include "vectornet/link/ethernet.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>

namespace {

using vectornet::link::EthernetFrameView;
using vectornet::link::EthernetStatus;
using vectornet::link::MacAddress;

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

[[nodiscard]] bool test_round_trip_and_padding() {
    constexpr MacAddress destination{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    constexpr MacAddress source{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    constexpr std::array<std::byte, 4> payload{
        std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    std::array<std::byte, 64> storage{};
    storage.fill(std::byte{0xA5});
    std::size_t frame_bytes = 0;
    if (!expect(
            vectornet::link::build_ethernet_frame(
                destination,
                source,
                vectornet::link::kEtherTypeIpv4,
                payload,
                storage,
                frame_bytes) == EthernetStatus::ok,
            "build failed") ||
        !expect(
            frame_bytes == vectornet::link::kEthernetMinimumFrameBytes,
            "minimum-frame padding missing")) {
        return false;
    }

    EthernetFrameView parsed{};
    if (!expect(
            vectornet::link::parse_ethernet_frame(
                std::span<const std::byte>(storage.data(), frame_bytes), parsed) ==
                EthernetStatus::ok,
            "parse failed") ||
        !expect(parsed.header.destination == destination, "destination mismatch") ||
        !expect(parsed.header.source == source, "source mismatch") ||
        !expect(
            parsed.header.ether_type == vectornet::link::kEtherTypeIpv4,
            "EtherType mismatch") ||
        !expect(parsed.payload.size() == frame_bytes - 14, "payload span mismatch")) {
        return false;
    }
    for (std::size_t index = 0; index < payload.size(); ++index) {
        if (!expect(parsed.payload[index] == payload[index], "payload byte mismatch")) {
            return false;
        }
    }
    for (std::size_t index = payload.size(); index < parsed.payload.size(); ++index) {
        if (!expect(parsed.payload[index] == std::byte{0}, "padding not zeroed")) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool test_rejections() {
    EthernetFrameView parsed{};
    std::array<std::byte, 13> short_frame{};
    if (!expect(
            vectornet::link::parse_ethernet_frame(short_frame, parsed) ==
                EthernetStatus::frame_too_short,
            "short frame accepted")) {
        return false;
    }

    std::array<std::byte, 60> vlan_frame{};
    vlan_frame[12] = std::byte{0x81};
    vlan_frame[13] = std::byte{0x00};
    if (!expect(
            vectornet::link::parse_ethernet_frame(vlan_frame, parsed) ==
                EthernetStatus::unsupported_vlan,
            "802.1Q frame accepted")) {
        return false;
    }
    vlan_frame[12] = std::byte{0x88};
    vlan_frame[13] = std::byte{0xA8};
    if (!expect(
            vectornet::link::parse_ethernet_frame(vlan_frame, parsed) ==
                EthernetStatus::unsupported_vlan,
            "802.1ad frame accepted")) {
        return false;
    }

    constexpr MacAddress address{};
    std::array<std::byte, 59> output{};
    std::size_t frame_bytes = 99;
    if (!expect(
            vectornet::link::build_ethernet_frame(
                address,
                address,
                vectornet::link::kEtherTypeIpv4,
                {},
                output,
                frame_bytes) == EthernetStatus::output_too_small,
            "undersized output accepted") ||
        !expect(frame_bytes == 0, "failure reported nonzero frame length") ||
        !expect(
            vectornet::link::build_ethernet_frame(
                address,
                address,
                vectornet::link::kEtherTypeVlan8021Q,
                {},
                output,
                frame_bytes) == EthernetStatus::unsupported_vlan,
            "VLAN builder accepted unsupported framing")) {
        return false;
    }
    return true;
}

}  // namespace

int main() {
    return test_round_trip_and_padding() && test_rejections() ? 0 : 1;
}

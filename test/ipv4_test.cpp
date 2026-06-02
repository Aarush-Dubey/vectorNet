#include "vectornet/net/ipv4.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>

namespace {

using vectornet::net::Ipv4PacketView;
using vectornet::net::Ipv4Status;

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

[[nodiscard]] bool test_known_checksum_vector() {
    std::array<std::byte, 20> header{
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x73},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x40}, std::byte{0x00},
        std::byte{0x40}, std::byte{0x11}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xC0}, std::byte{0xA8}, std::byte{0x00}, std::byte{0x01},
        std::byte{0xC0}, std::byte{0xA8}, std::byte{0x00}, std::byte{0xC7},
    };
    if (!expect(
            vectornet::net::internet_checksum(header) == 0xB861U,
            "known IPv4 checksum differs from 0xb861")) {
        return false;
    }
    header[10] = std::byte{0xB8};
    header[11] = std::byte{0x61};
    return expect(
        vectornet::net::internet_checksum(header) == 0,
        "checksummed reference header did not fold to zero");
}

[[nodiscard]] bool test_round_trip_and_padding_trim() {
    constexpr std::array<std::byte, 3> payload{
        std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
    const vectornet::net::Ipv4Header header{
        .dscp_ecn = 0x2E,
        .identification = 0x1234,
        .flags_fragment_offset = 0x4000,
        .ttl = vectornet::net::kVectorNetTtl,
        .protocol = vectornet::net::kVectorNetProtocol,
        .source = 0xC6130001U,
        .destination = 0xC6130002U,
    };
    std::array<std::byte, 64> packet{};
    packet.fill(std::byte{0xEE});
    std::size_t bytes = 0;
    if (!expect(
            vectornet::net::build_ipv4_packet(
                header, payload, packet, bytes) == Ipv4Status::ok,
            "IPv4 build failed") ||
        !expect(bytes == 23, "IPv4 total size mismatch") ||
        !expect(packet[0] == std::byte{0x45}, "IPv4 version/IHL mismatch") ||
        !expect(packet[2] == std::byte{0x00} && packet[3] == std::byte{0x17},
                "IPv4 total length byte order mismatch") ||
        !expect(
            vectornet::net::internet_checksum(
                std::span<const std::byte>(packet.data(), 20)) == 0,
            "serialized IPv4 checksum invalid")) {
        return false;
    }

    Ipv4PacketView parsed{};
    if (!expect(
            vectornet::net::parse_ipv4_packet(packet, parsed) == Ipv4Status::ok,
            "IPv4 parse failed") ||
        !expect(parsed.header.total_length == bytes, "parsed total length mismatch") ||
        !expect(parsed.header.identification == 0x1234, "parsed ID mismatch") ||
        !expect(parsed.header.flags_fragment_offset == 0x4000, "parsed flags mismatch") ||
        !expect(parsed.header.ttl == 64, "parsed TTL mismatch") ||
        !expect(parsed.header.protocol == 253, "parsed protocol mismatch") ||
        !expect(parsed.header.source == 0xC6130001U, "parsed source mismatch") ||
        !expect(parsed.header.destination == 0xC6130002U,
                "parsed destination mismatch") ||
        !expect(parsed.payload.size() == payload.size(),
                "Ethernet-style padding was not trimmed")) {
        return false;
    }
    if (!expect(
            std::equal(payload.begin(), payload.end(), parsed.payload.begin()),
            "parsed payload mismatch")) {
        return false;
    }
    packet[8] = std::byte{63};
    return expect(
        vectornet::net::parse_ipv4_packet(packet, parsed) ==
            Ipv4Status::invalid_checksum,
        "corrupted IPv4 header checksum accepted");
}

[[nodiscard]] bool test_rejections() {
    std::array<std::byte, 20> packet{};
    Ipv4PacketView parsed{};
    if (!expect(
            vectornet::net::parse_ipv4_packet(
                std::span<const std::byte>(packet.data(), 19), parsed) ==
                Ipv4Status::truncated,
            "truncated IPv4 header accepted")) {
        return false;
    }

    packet[0] = std::byte{0x65};
    if (!expect(
            vectornet::net::parse_ipv4_packet(packet, parsed) ==
                Ipv4Status::unsupported_version,
            "IPv6 version nibble accepted")) {
        return false;
    }
    packet[0] = std::byte{0x46};
    if (!expect(
            vectornet::net::parse_ipv4_packet(packet, parsed) ==
                Ipv4Status::unsupported_options,
            "IPv4 options accepted")) {
        return false;
    }
    packet[0] = std::byte{0x45};
    packet[2] = std::byte{0x00};
    packet[3] = std::byte{0x13};
    return expect(
        vectornet::net::parse_ipv4_packet(packet, parsed) ==
            Ipv4Status::invalid_total_length,
        "too-small IPv4 total length accepted");
}

}  // namespace

int main() {
    return test_known_checksum_vector() && test_round_trip_and_padding_trim() &&
                   test_rejections()
               ? 0
               : 1;
}

#include "vectornet/net/ipv4.hpp"

#include <cstring>
#include <limits>

namespace vectornet::net {
namespace {

[[nodiscard]] std::uint16_t read_be16(const std::byte* bytes) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[0])) << 8U |
        std::to_integer<std::uint8_t>(bytes[1]));
}

[[nodiscard]] std::uint32_t read_be32(const std::byte* bytes) noexcept {
    return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[0])) << 24U |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[1])) << 16U |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) << 8U |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3]));
}

void write_be16(std::byte* bytes, std::uint16_t value) noexcept {
    bytes[0] = static_cast<std::byte>((value >> 8U) & 0xFFU);
    bytes[1] = static_cast<std::byte>(value & 0xFFU);
}

void write_be32(std::byte* bytes, std::uint32_t value) noexcept {
    bytes[0] = static_cast<std::byte>((value >> 24U) & 0xFFU);
    bytes[1] = static_cast<std::byte>((value >> 16U) & 0xFFU);
    bytes[2] = static_cast<std::byte>((value >> 8U) & 0xFFU);
    bytes[3] = static_cast<std::byte>(value & 0xFFU);
}

}  // namespace

std::uint16_t internet_checksum(std::span<const std::byte> bytes) noexcept {
    std::uint32_t sum = 0;
    std::size_t offset = 0;
    while (offset + 1 < bytes.size()) {
        sum += read_be16(bytes.data() + offset);
        sum = (sum & 0xFFFFU) + (sum >> 16U);
        offset += 2;
    }
    if (offset < bytes.size()) {
        sum += static_cast<std::uint32_t>(
                   std::to_integer<std::uint8_t>(bytes[offset]))
               << 8U;
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

Ipv4Status parse_ipv4_packet(
    std::span<const std::byte> packet,
    Ipv4PacketView& result) noexcept {
    result = {};
    if (packet.size() < kIpv4HeaderBytes) {
        return Ipv4Status::truncated;
    }
    const std::uint8_t version_ihl = std::to_integer<std::uint8_t>(packet[0]);
    if ((version_ihl >> 4U) != kIpv4Version) {
        return Ipv4Status::unsupported_version;
    }
    if ((version_ihl & 0x0FU) != kIpv4HeaderWords) {
        return Ipv4Status::unsupported_options;
    }
    const std::uint16_t total_length = read_be16(packet.data() + 2);
    if (total_length < kIpv4HeaderBytes || total_length > packet.size()) {
        return Ipv4Status::invalid_total_length;
    }
    if (internet_checksum(packet.first(kIpv4HeaderBytes)) != 0) {
        return Ipv4Status::invalid_checksum;
    }

    result.header = {
        .dscp_ecn = std::to_integer<std::uint8_t>(packet[1]),
        .total_length = total_length,
        .identification = read_be16(packet.data() + 4),
        .flags_fragment_offset = read_be16(packet.data() + 6),
        .ttl = std::to_integer<std::uint8_t>(packet[8]),
        .protocol = std::to_integer<std::uint8_t>(packet[9]),
        .checksum = read_be16(packet.data() + 10),
        .source = read_be32(packet.data() + 12),
        .destination = read_be32(packet.data() + 16),
    };
    result.payload = packet.subspan(
        kIpv4HeaderBytes,
        static_cast<std::size_t>(total_length) - kIpv4HeaderBytes);
    return Ipv4Status::ok;
}

Ipv4Status build_ipv4_packet(
    const Ipv4Header& header,
    std::span<const std::byte> payload,
    std::span<std::byte> output,
    std::size_t& packet_bytes) noexcept {
    packet_bytes = 0;
    constexpr std::size_t kMaximumPayload =
        std::numeric_limits<std::uint16_t>::max() - kIpv4HeaderBytes;
    if (payload.size() > kMaximumPayload) {
        return Ipv4Status::payload_too_large;
    }
    const std::size_t required = kIpv4HeaderBytes + payload.size();
    if (output.size() < required) {
        return Ipv4Status::output_too_small;
    }

    output[0] = static_cast<std::byte>(
        static_cast<std::uint8_t>(kIpv4Version << 4U) | kIpv4HeaderWords);
    output[1] = static_cast<std::byte>(header.dscp_ecn);
    write_be16(output.data() + 2, static_cast<std::uint16_t>(required));
    write_be16(output.data() + 4, header.identification);
    write_be16(output.data() + 6, header.flags_fragment_offset);
    output[8] = static_cast<std::byte>(header.ttl);
    output[9] = static_cast<std::byte>(header.protocol);
    output[10] = std::byte{0};
    output[11] = std::byte{0};
    write_be32(output.data() + 12, header.source);
    write_be32(output.data() + 16, header.destination);
    const std::uint16_t checksum =
        internet_checksum(output.first(kIpv4HeaderBytes));
    write_be16(output.data() + 10, checksum);
    if (!payload.empty()) {
        std::memcpy(output.data() + kIpv4HeaderBytes, payload.data(), payload.size());
    }
    packet_bytes = required;
    return Ipv4Status::ok;
}

}  // namespace vectornet::net

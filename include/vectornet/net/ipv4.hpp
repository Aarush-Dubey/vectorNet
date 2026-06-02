#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace vectornet::net {

using Ipv4Address = std::uint32_t;

inline constexpr std::size_t kIpv4HeaderBytes = 20;
inline constexpr std::uint8_t kIpv4Version = 4;
inline constexpr std::uint8_t kIpv4HeaderWords = 5;
inline constexpr std::uint8_t kVectorNetProtocol = 253;
inline constexpr std::uint8_t kVectorNetTtl = 64;

struct Ipv4Header {
    std::uint8_t dscp_ecn{0};
    std::uint16_t total_length{0};
    std::uint16_t identification{0};
    std::uint16_t flags_fragment_offset{0};
    std::uint8_t ttl{kVectorNetTtl};
    std::uint8_t protocol{kVectorNetProtocol};
    std::uint16_t checksum{0};
    Ipv4Address source{0};
    Ipv4Address destination{0};
};

struct Ipv4PacketView {
    Ipv4Header header{};
    std::span<const std::byte> payload{};
};

enum class Ipv4Status : std::uint8_t {
    ok,
    truncated,
    unsupported_version,
    unsupported_options,
    invalid_total_length,
    invalid_checksum,
    payload_too_large,
    output_too_small,
};

[[nodiscard]] std::uint16_t internet_checksum(
    std::span<const std::byte> bytes) noexcept;

[[nodiscard]] Ipv4Status parse_ipv4_packet(
    std::span<const std::byte> packet,
    Ipv4PacketView& result) noexcept;

[[nodiscard]] Ipv4Status build_ipv4_packet(
    const Ipv4Header& header,
    std::span<const std::byte> payload,
    std::span<std::byte> output,
    std::size_t& packet_bytes) noexcept;

}  // namespace vectornet::net

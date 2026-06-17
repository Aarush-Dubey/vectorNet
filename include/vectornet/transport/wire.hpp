#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace vectornet::transport {

inline constexpr std::size_t kTransportFixedHeaderBytes = 12;
inline constexpr std::size_t kSackBlockBytes = 8;
inline constexpr std::size_t kMaximumSackBlocks = 4;
inline constexpr std::size_t kMaximumTransportHeaderBytes =
    kTransportFixedHeaderBytes + kMaximumSackBlocks * kSackBlockBytes;

inline constexpr std::uint8_t kFlagSyn = 0x01;
inline constexpr std::uint8_t kFlagAck = 0x02;
inline constexpr std::uint8_t kFlagFin = 0x04;
inline constexpr std::uint8_t kFlagRst = 0x08;
inline constexpr std::uint8_t kKnownFlags =
    kFlagSyn | kFlagAck | kFlagFin | kFlagRst;

struct SackBlock {
    std::uint32_t start{0};
    std::uint32_t end{0};

    [[nodiscard]] friend bool operator==(
        const SackBlock&,
        const SackBlock&) noexcept = default;
};

struct TransportHeader {
    std::uint32_t sequence{0};
    std::uint32_t cumulative_ack{0};
    std::uint8_t flags{0};
    std::uint8_t sack_count{0};
    std::uint16_t window{0};
    std::array<SackBlock, kMaximumSackBlocks> sacks{};

    [[nodiscard]] friend bool operator==(
        const TransportHeader&,
        const TransportHeader&) noexcept = default;
};

enum class WireStatus : std::uint8_t {
    ok,
    buffer_too_small,
    invalid_flags,
    too_many_sacks,
    invalid_sack_range,
};

[[nodiscard]] WireStatus serialize_transport_header(
    const TransportHeader& header,
    std::span<std::byte> output,
    std::size_t& bytes_written) noexcept;

[[nodiscard]] WireStatus parse_transport_header(
    std::span<const std::byte> input,
    TransportHeader& header,
    std::size_t& bytes_consumed) noexcept;

}  // namespace vectornet::transport

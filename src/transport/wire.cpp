#include "vectornet/transport/wire.hpp"

namespace vectornet::transport {
namespace {

void write_u16(std::span<std::byte> output, std::size_t offset, std::uint16_t value) {
    output[offset] = static_cast<std::byte>(value >> 8U);
    output[offset + 1] = static_cast<std::byte>(value & 0xFFU);
}

void write_u32(std::span<std::byte> output, std::size_t offset, std::uint32_t value) {
    output[offset] = static_cast<std::byte>(value >> 24U);
    output[offset + 1] = static_cast<std::byte>((value >> 16U) & 0xFFU);
    output[offset + 2] = static_cast<std::byte>((value >> 8U) & 0xFFU);
    output[offset + 3] = static_cast<std::byte>(value & 0xFFU);
}

[[nodiscard]] std::uint16_t read_u16(
    std::span<const std::byte> input,
    std::size_t offset) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(input[offset]) << 8U) |
        static_cast<std::uint16_t>(input[offset + 1]));
}

[[nodiscard]] std::uint32_t read_u32(
    std::span<const std::byte> input,
    std::size_t offset) {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
        (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
        (static_cast<std::uint32_t>(input[offset + 2]) << 8U) |
        static_cast<std::uint32_t>(input[offset + 3]);
}

[[nodiscard]] WireStatus validate(const TransportHeader& header) noexcept {
    if ((header.flags & static_cast<std::uint8_t>(~kKnownFlags)) != 0) {
        return WireStatus::invalid_flags;
    }
    if (header.sack_count > kMaximumSackBlocks) {
        return WireStatus::too_many_sacks;
    }
    for (std::size_t index = 0; index < header.sack_count; ++index) {
        if (header.sacks[index].start == header.sacks[index].end) {
            return WireStatus::invalid_sack_range;
        }
    }
    return WireStatus::ok;
}

}  // namespace

WireStatus serialize_transport_header(
    const TransportHeader& header,
    std::span<std::byte> output,
    std::size_t& bytes_written) noexcept {
    bytes_written = 0;
    const WireStatus status = validate(header);
    if (status != WireStatus::ok) {
        return status;
    }
    const std::size_t needed = kTransportFixedHeaderBytes +
        static_cast<std::size_t>(header.sack_count) * kSackBlockBytes;
    if (output.size() < needed) {
        return WireStatus::buffer_too_small;
    }
    write_u32(output, 0, header.sequence);
    write_u32(output, 4, header.cumulative_ack);
    output[8] = static_cast<std::byte>(header.flags);
    output[9] = static_cast<std::byte>(header.sack_count);
    write_u16(output, 10, header.window);
    for (std::size_t index = 0; index < header.sack_count; ++index) {
        const std::size_t offset = kTransportFixedHeaderBytes + index * kSackBlockBytes;
        write_u32(output, offset, header.sacks[index].start);
        write_u32(output, offset + 4, header.sacks[index].end);
    }
    bytes_written = needed;
    return WireStatus::ok;
}

WireStatus parse_transport_header(
    std::span<const std::byte> input,
    TransportHeader& header,
    std::size_t& bytes_consumed) noexcept {
    bytes_consumed = 0;
    if (input.size() < kTransportFixedHeaderBytes) {
        return WireStatus::buffer_too_small;
    }
    TransportHeader parsed{
        .sequence = read_u32(input, 0),
        .cumulative_ack = read_u32(input, 4),
        .flags = static_cast<std::uint8_t>(input[8]),
        .sack_count = static_cast<std::uint8_t>(input[9]),
        .window = read_u16(input, 10),
    };
    if (parsed.sack_count > kMaximumSackBlocks) {
        return WireStatus::too_many_sacks;
    }
    const std::size_t needed = kTransportFixedHeaderBytes +
        static_cast<std::size_t>(parsed.sack_count) * kSackBlockBytes;
    if (input.size() < needed) {
        return WireStatus::buffer_too_small;
    }
    for (std::size_t index = 0; index < parsed.sack_count; ++index) {
        const std::size_t offset = kTransportFixedHeaderBytes + index * kSackBlockBytes;
        parsed.sacks[index] = SackBlock{
            .start = read_u32(input, offset),
            .end = read_u32(input, offset + 4),
        };
    }
    const WireStatus status = validate(parsed);
    if (status != WireStatus::ok) {
        return status;
    }
    header = parsed;
    bytes_consumed = needed;
    return WireStatus::ok;
}

}  // namespace vectornet::transport

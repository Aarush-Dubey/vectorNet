#include "vectornet/transport/wire.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iostream>
#include <span>

namespace {

using vectornet::transport::WireStatus;

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

template <std::size_t Size>
[[nodiscard]] bool golden_round_trip(
    const vectornet::transport::TransportHeader& header,
    const std::array<std::byte, Size>& expected) {
    std::array<std::byte, vectornet::transport::kMaximumTransportHeaderBytes> output{};
    std::size_t written = 0;
    if (!expect(
            vectornet::transport::serialize_transport_header(
                header, output, written) == WireStatus::ok,
            "golden serialize failed") ||
        !expect(written == expected.size(), "golden serialized size mismatch") ||
        !expect(std::equal(expected.begin(), expected.end(), output.begin()),
                "golden serialized bytes mismatch")) {
        return false;
    }
    vectornet::transport::TransportHeader parsed{};
    std::size_t consumed = 0;
    return expect(
               vectornet::transport::parse_transport_header(
                   std::span<const std::byte>(output.data(), written),
                   parsed,
                   consumed) == WireStatus::ok,
               "golden parse failed") &&
           expect(consumed == written, "golden consumed size mismatch") &&
           expect(parsed == header, "golden round-trip mismatch");
}

}  // namespace

int main() {
    const vectornet::transport::TransportHeader zero_sack{
        .sequence = 0x01020304,
        .cumulative_ack = 0xA0B0C0D0,
        .flags = vectornet::transport::kFlagSyn |
            vectornet::transport::kFlagAck,
        .sack_count = 0,
        .window = 0x1234,
    };
    const std::array<std::byte, 12> zero_golden{
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0xA0}, std::byte{0xB0}, std::byte{0xC0}, std::byte{0xD0},
        std::byte{0x03}, std::byte{0x00}, std::byte{0x12}, std::byte{0x34},
    };
    if (!golden_round_trip(zero_sack, zero_golden)) {
        return 1;
    }

    const vectornet::transport::TransportHeader four_sacks{
        .sequence = 0x11223344,
        .cumulative_ack = 0x55667788,
        .flags = vectornet::transport::kFlagAck,
        .sack_count = 4,
        .window = 0xFFFF,
        .sacks = {{{1, 9}, {16, 32}, {0x10203040, 0x10203050},
                   {0xFFFFFFF0, 0x00000010}}},
    };
    const std::array<std::byte, 44> four_golden{
        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88},
        std::byte{0x02}, std::byte{0x04}, std::byte{0xFF}, std::byte{0xFF},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x09},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x10},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x20},
        std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x40},
        std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x50},
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xF0},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x10},
    };
    if (!golden_round_trip(four_sacks, four_golden)) {
        return 1;
    }

    auto invalid = zero_sack;
    invalid.flags = 0x80;
    std::array<std::byte, 44> output{};
    std::size_t written = 0;
    if (!expect(
            vectornet::transport::serialize_transport_header(
                invalid, output, written) == WireStatus::invalid_flags,
            "unknown flag accepted")) {
        return 1;
    }
    invalid = zero_sack;
    invalid.sack_count = 1;
    invalid.sacks[0] = {5, 5};
    return expect(
               vectornet::transport::serialize_transport_header(
                   invalid, output, written) == WireStatus::invalid_sack_range,
               "empty SACK range accepted")
               ? 0
               : 1;
}

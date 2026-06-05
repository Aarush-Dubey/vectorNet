#include "vectornet/net/ipv4.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>

namespace {

using vectornet::net::Ipv4Status;

struct FragmentLog {
    std::array<std::array<std::byte, 1'500>, 8> packets{};
    std::array<std::size_t, 8> packet_bytes{};
    std::size_t count{0};
};

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

bool collect_fragment(void* opaque, std::span<const std::byte> packet) noexcept {
    auto& log = *static_cast<FragmentLog*>(opaque);
    if (log.count >= log.packets.size() ||
        packet.size() > log.packets[log.count].size()) {
        return false;
    }
    std::copy(packet.begin(), packet.end(), log.packets[log.count].begin());
    log.packet_bytes[log.count] = packet.size();
    ++log.count;
    return true;
}

[[nodiscard]] vectornet::net::Ipv4Header base_header() {
    return {
        .identification = 0x1234,
        .ttl = vectornet::net::kVectorNetTtl,
        .protocol = vectornet::net::kVectorNetProtocol,
        .source = 0xC6130001U,
        .destination = 0xC6130002U,
    };
}

[[nodiscard]] bool test_fragment_shapes_and_reassembly() {
    std::array<std::byte, 4'000> payload{};
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>(index & 0xFFU);
    }
    std::array<std::byte, 1'500> scratch{};
    FragmentLog log{};
    if (!expect(
            vectornet::net::fragment_ipv4_payload(
                base_header(),
                payload,
                1'500,
                scratch,
                &collect_fragment,
                &log) == Ipv4Status::ok,
            "fragmentation failed") ||
        !expect(log.count == 3, "fragment count mismatch") ||
        !expect(log.packet_bytes[0] == 1'500, "first fragment size mismatch") ||
        !expect(log.packet_bytes[1] == 1'500, "second fragment size mismatch") ||
        !expect(log.packet_bytes[2] == 1'060, "last fragment size mismatch")) {
        return false;
    }

    constexpr std::array<std::uint16_t, 3> expected_offsets{0, 185, 370};
    std::array<std::byte, 4'000> reconstructed{};
    for (std::size_t index = 0; index < log.count; ++index) {
        vectornet::net::Ipv4PacketView fragment{};
        if (!expect(
                vectornet::net::parse_ipv4_packet(
                    std::span<const std::byte>(
                        log.packets[index].data(), log.packet_bytes[index]),
                    fragment) == Ipv4Status::ok,
                "generated fragment did not parse") ||
            !expect(fragment.header.identification == 0x1234,
                    "fragment ID mismatch") ||
            !expect(
                (fragment.header.flags_fragment_offset &
                 vectornet::net::kIpv4FragmentOffsetMask) == expected_offsets[index],
                "fragment offset mismatch")) {
            return false;
        }
        const bool more =
            (fragment.header.flags_fragment_offset &
             vectornet::net::kIpv4FlagMoreFragments) != 0;
        if (!expect(more == (index + 1 < log.count), "MF flag mismatch") ||
            !expect(!more || fragment.payload.size() % 8U == 0,
                    "non-final fragment lacks eight-byte alignment")) {
            return false;
        }
        const std::size_t byte_offset =
            static_cast<std::size_t>(expected_offsets[index]) * 8U;
        std::copy(
            fragment.payload.begin(),
            fragment.payload.end(),
            reconstructed.begin() + static_cast<std::ptrdiff_t>(byte_offset));
    }
    return expect(reconstructed == payload, "fragment set did not reconstruct payload");
}

[[nodiscard]] bool test_boundary_shapes() {
    std::array<std::byte, 1'481> payload{};
    std::array<std::byte, 1'500> scratch{};
    FragmentLog log{};
    if (!expect(
            vectornet::net::fragment_ipv4_payload(
                base_header(),
                payload,
                1'500,
                scratch,
                &collect_fragment,
                &log) == Ipv4Status::ok,
            "boundary fragmentation failed") ||
        !expect(log.count == 2, "1481-byte payload did not split") ||
        !expect(log.packet_bytes[0] == 1'500, "boundary first size mismatch") ||
        !expect(log.packet_bytes[1] == 21, "boundary last size mismatch")) {
        return false;
    }

    FragmentLog invalid{};
    std::array<std::byte, 20> tiny_scratch{};
    return expect(
        vectornet::net::fragment_ipv4_payload(
            base_header(),
            std::span<const std::byte>(payload.data(), 1),
            20,
            tiny_scratch,
            &collect_fragment,
            &invalid) == Ipv4Status::invalid_mtu,
        "MTU without aligned fragment payload accepted");
}

[[nodiscard]] bool test_identification_wrap() {
    vectornet::net::Ipv4IdentificationGenerator ids(0xFFFEU);
    return expect(ids.next() == 0xFFFEU, "first identification mismatch") &&
           expect(ids.next() == 0xFFFFU, "second identification mismatch") &&
           expect(ids.next() == 0, "identification did not wrap");
}

}  // namespace

int main() {
    return test_fragment_shapes_and_reassembly() && test_boundary_shapes() &&
                   test_identification_wrap()
               ? 0
               : 1;
}

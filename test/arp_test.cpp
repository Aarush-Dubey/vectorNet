#include "vectornet/link/arp.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <system_error>

namespace {

using vectornet::link::ArpMessage;
using vectornet::link::ArpOperation;
using vectornet::link::ArpStatus;
using vectornet::link::Ipv4Address;
using vectornet::link::MacAddress;

struct Mailbox {
    MacAddress destination{};
    std::array<std::byte, vectornet::link::kArpPayloadBytes> payload{};
    std::size_t bytes{0};
    std::size_t sends{0};
};

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

std::error_code transmit_to_mailbox(
    void* opaque,
    const MacAddress& destination,
    std::span<const std::byte> payload) noexcept {
    auto& mailbox = *static_cast<Mailbox*>(opaque);
    if (payload.size() > mailbox.payload.size()) {
        return std::make_error_code(std::errc::message_size);
    }
    mailbox.destination = destination;
    mailbox.bytes = payload.size();
    ++mailbox.sends;
    for (std::size_t index = 0; index < payload.size(); ++index) {
        mailbox.payload[index] = payload[index];
    }
    return {};
}

[[nodiscard]] bool test_wire_format() {
    constexpr MacAddress sender{0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    constexpr Ipv4Address sender_ip = 0xC6130001U;
    constexpr Ipv4Address target_ip = 0xC6130002U;
    const ArpMessage request{
        .operation = ArpOperation::request,
        .sender_hardware = sender,
        .sender_protocol = sender_ip,
        .target_hardware = {},
        .target_protocol = target_ip,
    };
    std::array<std::byte, vectornet::link::kArpPayloadBytes> output{};
    std::size_t bytes = 0;
    if (!expect(
            vectornet::link::build_arp_message(request, output, bytes) == ArpStatus::ok,
            "ARP request build failed") ||
        !expect(bytes == output.size(), "ARP request length mismatch") ||
        !expect(output[0] == std::byte{0x00} && output[1] == std::byte{0x01},
                "ARP hardware type mismatch") ||
        !expect(output[2] == std::byte{0x08} && output[3] == std::byte{0x00},
                "ARP protocol type mismatch") ||
        !expect(output[6] == std::byte{0x00} && output[7] == std::byte{0x01},
                "ARP operation mismatch") ||
        !expect(output[14] == std::byte{0xC6} && output[17] == std::byte{0x01},
                "ARP sender IP byte order mismatch") ||
        !expect(output[24] == std::byte{0xC6} && output[27] == std::byte{0x02},
                "ARP target IP byte order mismatch")) {
        return false;
    }

    ArpMessage parsed{};
    return expect(
               vectornet::link::parse_arp_message(output, parsed) == ArpStatus::ok,
               "ARP request parse failed") &&
           expect(parsed.operation == request.operation, "ARP parsed operation mismatch") &&
           expect(parsed.sender_hardware == sender, "ARP parsed sender MAC mismatch") &&
           expect(parsed.sender_protocol == sender_ip, "ARP parsed sender IP mismatch") &&
           expect(parsed.target_protocol == target_ip, "ARP parsed target IP mismatch");
}

[[nodiscard]] bool test_resolution_exchange_and_expiry() {
    constexpr MacAddress mac_a{0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    constexpr MacAddress mac_b{0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    constexpr Ipv4Address ip_a = 0xC6130001U;
    constexpr Ipv4Address ip_b = 0xC6130002U;
    constexpr std::uint64_t ttl = 100;
    Mailbox a_to_b{};
    Mailbox b_to_a{};
    vectornet::link::ArpResolver a(
        ip_a, mac_a, 4, &transmit_to_mailbox, &a_to_b, ttl);
    vectornet::link::ArpResolver b(
        ip_b, mac_b, 4, &transmit_to_mailbox, &b_to_a, ttl);

    const auto first = a.resolve(ip_b, 10);
    if (!expect(first.status == ArpStatus::pending && !first.hardware.has_value(),
                "initial resolve did not become pending") ||
        !expect(a_to_b.sends == 1, "ARP request not sent") ||
        !expect(a_to_b.destination == vectornet::link::kEthernetBroadcast,
                "ARP request not broadcast") ||
        !expect(
            b.on_arp_payload(
                std::span<const std::byte>(a_to_b.payload.data(), a_to_b.bytes), 11) ==
                ArpStatus::ok,
            "peer rejected ARP request") ||
        !expect(b_to_a.sends == 1 && b_to_a.destination == mac_a,
                "peer did not unicast ARP reply") ||
        !expect(
            a.on_arp_payload(
                std::span<const std::byte>(b_to_a.payload.data(), b_to_a.bytes), 12) ==
                ArpStatus::ok,
            "requester rejected ARP reply")) {
        return false;
    }

    const auto resolved = a.resolve(ip_b, 50);
    if (!expect(resolved.status == ArpStatus::ok, "cached resolve missed") ||
        !expect(resolved.hardware == mac_b, "cached resolve returned wrong MAC") ||
        !expect(a_to_b.sends == 1, "cache hit sent another ARP request") ||
        !expect(a.cache().active_entries(50) == 1, "cache active count mismatch")) {
        return false;
    }

    const auto expired = a.resolve(ip_b, 112);
    return expect(expired.status == ArpStatus::pending, "expired entry returned hit") &&
           expect(!expired.hardware.has_value(), "expired entry retained MAC") &&
           expect(a_to_b.sends == 2, "expiry did not trigger new ARP request");
}

[[nodiscard]] bool test_bounded_cache_and_malformed_input() {
    constexpr MacAddress mac{0x02, 0, 0, 0, 0, 1};
    vectornet::link::ArpCache cache(1, 10);
    if (!expect(cache.capacity() == 1, "cache capacity mismatch") ||
        !expect(cache.insert(1, mac, 0), "first cache insert failed") ||
        !expect(!cache.insert(2, mac, 1), "full cache accepted second entry") ||
        !expect(cache.insert(2, mac, 10), "expired slot not reused")) {
        return false;
    }

    std::array<std::byte, vectornet::link::kArpPayloadBytes> malformed{};
    ArpMessage message{};
    if (!expect(
            vectornet::link::parse_arp_message(
                std::span<const std::byte>(malformed.data(), 27), message) ==
                ArpStatus::malformed,
            "short ARP payload accepted")) {
        return false;
    }
    malformed[0] = std::byte{0x00};
    malformed[1] = std::byte{0x02};
    if (!expect(
            vectornet::link::parse_arp_message(malformed, message) ==
                ArpStatus::unsupported,
            "unsupported ARP hardware accepted")) {
        return false;
    }

    Mailbox replies{};
    vectornet::link::ArpResolver zero_capacity(
        2, mac, 0, &transmit_to_mailbox, &replies, 10);
    const ArpMessage request{
        .operation = ArpOperation::request,
        .sender_hardware = MacAddress{0x02, 0, 0, 0, 0, 2},
        .sender_protocol = 1,
        .target_hardware = {},
        .target_protocol = 2,
    };
    std::array<std::byte, vectornet::link::kArpPayloadBytes> request_bytes{};
    std::size_t request_size = 0;
    if (!expect(
            vectornet::link::build_arp_message(
                request, request_bytes, request_size) == ArpStatus::ok,
            "bounded-cache request build failed")) {
        return false;
    }
    return expect(
               zero_capacity.on_arp_payload(
                   std::span<const std::byte>(request_bytes.data(), request_size), 0) ==
                   ArpStatus::cache_full,
               "zero-capacity resolver did not report cache pressure") &&
           expect(replies.sends == 1, "cache pressure suppressed required ARP reply");
}

}  // namespace

int main() {
    return test_wire_format() && test_resolution_exchange_and_expiry() &&
                   test_bounded_cache_and_malformed_input()
               ? 0
               : 1;
}

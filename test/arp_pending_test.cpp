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

struct ArpMailbox {
    MacAddress destination{};
    std::array<std::byte, vectornet::link::kArpPayloadBytes> payload{};
    std::size_t bytes{0};
    std::size_t sends{0};
};

struct FrameRecord {
    MacAddress destination{};
    std::uint16_t ether_type{0};
    std::array<std::byte, 32> payload{};
    std::size_t bytes{0};
};

struct FrameLog {
    std::array<FrameRecord, 8> records{};
    std::size_t sends{0};
};

struct FailureLog {
    Ipv4Address target{0};
    ArpStatus reason{ArpStatus::ok};
    std::size_t calls{0};
};

struct DirectEndpoint {
    vectornet::link::ArpResolver* peer{nullptr};
    std::uint64_t delivery_time{0};
    std::size_t sends{0};
};

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

std::error_code send_arp(
    void* opaque,
    const MacAddress& destination,
    std::span<const std::byte> payload) noexcept {
    auto& mailbox = *static_cast<ArpMailbox*>(opaque);
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

std::error_code send_frame(
    void* opaque,
    const MacAddress& destination,
    std::uint16_t ether_type,
    std::span<const std::byte> payload) noexcept {
    auto& log = *static_cast<FrameLog*>(opaque);
    if (log.sends >= log.records.size() ||
        payload.size() > log.records[log.sends].payload.size()) {
        return std::make_error_code(std::errc::no_buffer_space);
    }
    auto& record = log.records[log.sends];
    record.destination = destination;
    record.ether_type = ether_type;
    record.bytes = payload.size();
    for (std::size_t index = 0; index < payload.size(); ++index) {
        record.payload[index] = payload[index];
    }
    ++log.sends;
    return {};
}

void record_failure(
    void* opaque,
    Ipv4Address target,
    ArpStatus reason) noexcept {
    auto& log = *static_cast<FailureLog*>(opaque);
    log.target = target;
    log.reason = reason;
    ++log.calls;
}

std::error_code send_arp_direct(
    void* opaque,
    const MacAddress&,
    std::span<const std::byte> payload) noexcept {
    auto& endpoint = *static_cast<DirectEndpoint*>(opaque);
    ++endpoint.sends;
    if (endpoint.peer == nullptr) {
        return std::make_error_code(std::errc::not_connected);
    }
    const ArpStatus status =
        endpoint.peer->on_arp_payload(payload, endpoint.delivery_time);
    return status == ArpStatus::ok
        ? std::error_code{}
        : std::make_error_code(std::errc::protocol_error);
}

[[nodiscard]] vectornet::link::ArpResolverConfig test_config() {
    return {
        .cache_capacity = 4,
        .pending_capacity = 4,
        .ttl_ns = 100,
        .refresh_margin_ns = 20,
        .retry_interval_ns = 10,
        .pending_deadline_ns = 40,
        .maximum_attempts = 3,
    };
}

[[nodiscard]] bool test_pending_flush_without_loss() {
    constexpr MacAddress mac_a{0x02, 0, 0, 0, 0, 1};
    constexpr MacAddress mac_b{0x02, 0, 0, 0, 0, 2};
    constexpr Ipv4Address ip_a = 0xC6130001U;
    constexpr Ipv4Address ip_b = 0xC6130002U;
    constexpr std::array<std::byte, 3> first{
        std::byte{1}, std::byte{2}, std::byte{3}};
    constexpr std::array<std::byte, 2> second{std::byte{4}, std::byte{5}};
    ArpMailbox a_to_b{};
    ArpMailbox b_to_a{};
    FrameLog frames{};
    FailureLog failures{};
    const auto config = test_config();
    vectornet::link::ArpResolver a(
        ip_a,
        mac_a,
        config,
        {
            .arp_transmit = &send_arp,
            .arp_context = &a_to_b,
            .frame_transmit = &send_frame,
            .frame_context = &frames,
            .failure = &record_failure,
            .failure_context = &failures,
        });
    vectornet::link::ArpResolver b(
        ip_b,
        mac_b,
        config,
        {.arp_transmit = &send_arp, .arp_context = &b_to_a});

    if (!expect(
            a.queue_frame(ip_b, vectornet::link::kEtherTypeIpv4, first, 0) ==
                ArpStatus::queued,
            "first unresolved frame not queued") ||
        !expect(
            a.queue_frame(ip_b, vectornet::link::kEtherTypeIpv4, second, 1) ==
                ArpStatus::queued,
            "second unresolved frame not queued") ||
        !expect(a_to_b.sends == 1, "duplicate resolve request not suppressed") ||
        !expect(a.pending_frames() == 2, "pending count mismatch") ||
        !expect(a.active_resolutions() == 1, "resolution state mismatch") ||
        !expect(
            b.on_arp_payload(
                std::span<const std::byte>(a_to_b.payload.data(), a_to_b.bytes), 2) ==
                ArpStatus::ok,
            "peer rejected request") ||
        !expect(
            a.on_arp_payload(
                std::span<const std::byte>(b_to_a.payload.data(), b_to_a.bytes), 3) ==
                ArpStatus::ok,
            "requester rejected reply")) {
        return false;
    }
    if (!expect(frames.sends == 2, "pending frames not fully flushed") ||
        !expect(frames.records[0].destination == mac_b, "flush destination mismatch") ||
        !expect(frames.records[0].bytes == first.size(), "first flush size mismatch") ||
        !expect(frames.records[1].bytes == second.size(), "second flush size mismatch") ||
        !expect(a.pending_frames() == 0, "pending frames retained after resolve") ||
        !expect(a.active_resolutions() == 0, "resolution retained after reply") ||
        !expect(failures.calls == 0, "successful resolution reported failure")) {
        return false;
    }

    return expect(
               a.queue_frame(ip_b, vectornet::link::kEtherTypeIpv4, first, 4) ==
                   ArpStatus::ok,
               "cached frame not sent immediately") &&
           expect(frames.sends == 3, "cached send did not reach link callback") &&
           expect(a_to_b.sends == 1, "cached send emitted ARP request");
}

[[nodiscard]] bool test_retry_and_timeout() {
    constexpr MacAddress local_mac{0x02, 0, 0, 0, 0, 1};
    constexpr Ipv4Address target = 0xC6130002U;
    constexpr std::array<std::byte, 1> payload{std::byte{9}};
    ArpMailbox requests{};
    FrameLog frames{};
    FailureLog failures{};
    vectornet::link::ArpResolver resolver(
        0xC6130001U,
        local_mac,
        test_config(),
        {
            .arp_transmit = &send_arp,
            .arp_context = &requests,
            .frame_transmit = &send_frame,
            .frame_context = &frames,
            .failure = &record_failure,
            .failure_context = &failures,
        });
    if (!expect(
            resolver.queue_frame(
                target, vectornet::link::kEtherTypeIpv4, payload, 0) ==
                ArpStatus::queued,
            "timeout frame not queued") ||
        !expect(requests.sends == 1, "initial request count mismatch")) {
        return false;
    }
    resolver.tick(9);
    resolver.tick(10);
    resolver.tick(20);
    resolver.tick(30);
    if (!expect(requests.sends == 3, "retry count differs from three attempts") ||
        !expect(failures.calls == 0, "failure reported before deadline")) {
        return false;
    }
    resolver.tick(40);
    resolver.tick(50);
    return expect(failures.calls == 1, "timeout failure count mismatch") &&
           expect(failures.target == target, "timeout target mismatch") &&
           expect(failures.reason == ArpStatus::unreachable, "timeout reason mismatch") &&
           expect(resolver.pending_frames() == 0, "timed-out frame retained") &&
           expect(resolver.active_resolutions() == 0, "timed-out resolution retained") &&
           expect(frames.sends == 0, "timed-out frame reached link callback");
}

[[nodiscard]] bool test_refresh_and_gratuitous_learning() {
    constexpr MacAddress local_mac{0x02, 0, 0, 0, 0, 1};
    constexpr MacAddress peer_mac{0x02, 0, 0, 0, 0, 2};
    constexpr Ipv4Address local_ip = 0xC6130001U;
    constexpr Ipv4Address peer_ip = 0xC6130002U;
    ArpMailbox requests{};
    vectornet::link::ArpResolver resolver(
        local_ip,
        local_mac,
        test_config(),
        {.arp_transmit = &send_arp, .arp_context = &requests});
    if (!expect(resolver.cache().insert(peer_ip, peer_mac, 0), "cache seed failed")) {
        return false;
    }
    resolver.tick(79);
    resolver.tick(80);
    resolver.tick(81);
    if (!expect(requests.sends == 1, "refresh request timing/count mismatch") ||
        !expect(resolver.active_resolutions() == 1, "refresh state missing")) {
        return false;
    }

    const ArpMessage gratuitous{
        .operation = ArpOperation::request,
        .sender_hardware = peer_mac,
        .sender_protocol = peer_ip,
        .target_hardware = {},
        .target_protocol = peer_ip,
    };
    std::array<std::byte, vectornet::link::kArpPayloadBytes> bytes{};
    std::size_t size = 0;
    if (!expect(
            vectornet::link::build_arp_message(gratuitous, bytes, size) == ArpStatus::ok,
            "gratuitous ARP build failed") ||
        !expect(
            resolver.on_arp_payload(
                std::span<const std::byte>(bytes.data(), size), 82) == ArpStatus::ok,
            "gratuitous ARP rejected")) {
        return false;
    }
    const auto learned = resolver.cache().lookup(peer_ip, 150);
    return expect(learned == peer_mac, "gratuitous ARP did not refresh cache") &&
           expect(resolver.active_resolutions() == 0,
                  "gratuitous ARP did not finish refresh");
}

[[nodiscard]] bool test_reentrant_reply_flushes_published_slot() {
    constexpr MacAddress mac_a{0x02, 0, 0, 0, 0, 1};
    constexpr MacAddress mac_b{0x02, 0, 0, 0, 0, 2};
    constexpr Ipv4Address ip_a = 0xC6130001U;
    constexpr Ipv4Address ip_b = 0xC6130002U;
    constexpr std::array<std::byte, 2> payload{std::byte{7}, std::byte{8}};
    DirectEndpoint a_out{.delivery_time = 2};
    DirectEndpoint b_out{.delivery_time = 3};
    FrameLog frames{};
    vectornet::link::ArpResolver a(
        ip_a,
        mac_a,
        test_config(),
        {
            .arp_transmit = &send_arp_direct,
            .arp_context = &a_out,
            .frame_transmit = &send_frame,
            .frame_context = &frames,
        });
    vectornet::link::ArpResolver b(
        ip_b,
        mac_b,
        test_config(),
        {.arp_transmit = &send_arp_direct, .arp_context = &b_out});
    a_out.peer = &b;
    b_out.peer = &a;

    return expect(
               a.queue_frame(ip_b, vectornet::link::kEtherTypeIpv4, payload, 1) ==
                   ArpStatus::queued,
               "reentrant queue failed") &&
           expect(a_out.sends == 1 && b_out.sends == 1,
                  "reentrant ARP exchange count mismatch") &&
           expect(frames.sends == 1, "reentrant reply lost pending frame") &&
           expect(a.pending_frames() == 0, "reentrant reply left pending frame") &&
           expect(a.active_resolutions() == 0,
                  "reentrant reply left resolution state");
}

[[nodiscard]] bool test_queue_bounds() {
    constexpr MacAddress local_mac{0x02, 0, 0, 0, 0, 1};
    ArpMailbox requests{};
    FrameLog frames{};
    auto config = test_config();
    config.pending_capacity = 1;
    vectornet::link::ArpResolver resolver(
        0xC6130001U,
        local_mac,
        config,
        {
            .arp_transmit = &send_arp,
            .arp_context = &requests,
            .frame_transmit = &send_frame,
            .frame_context = &frames,
        });
    constexpr std::array<std::byte, 1> small{std::byte{1}};
    std::array<std::byte, vectornet::link::kArpMaximumPendingPayloadBytes + 1>
        oversized{};
    return expect(
               resolver.queue_frame(
                   2, vectornet::link::kEtherTypeIpv4, oversized, 0) ==
                   ArpStatus::payload_too_large,
               "oversized pending payload accepted") &&
           expect(
               resolver.queue_frame(2, vectornet::link::kEtherTypeIpv4, small, 0) ==
                   ArpStatus::queued,
               "bounded queue rejected first frame") &&
           expect(
               resolver.queue_frame(3, vectornet::link::kEtherTypeIpv4, small, 0) ==
                   ArpStatus::queue_full,
               "bounded queue accepted excess frame");
}

}  // namespace

int main() {
    return test_pending_flush_without_loss() && test_retry_and_timeout() &&
                   test_refresh_and_gratuitous_learning() &&
                   test_reentrant_reply_flushes_published_slot() &&
                   test_queue_bounds()
               ? 0
               : 1;
}

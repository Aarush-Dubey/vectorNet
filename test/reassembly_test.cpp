#include "vectornet/net/ipv4.hpp"
#include "vectornet/net/reassembly.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>

namespace {

using vectornet::net::Ipv4Status;
using vectornet::net::ReassemblyStatus;

struct FragmentLog {
    std::array<std::array<std::byte, 1'500>, 4> packets{};
    std::array<std::size_t, 4> bytes{};
    std::size_t count{0};
};

struct Delivery {
    vectornet::net::ReassemblyKey key{};
    std::array<std::byte, 4'000> payload{};
    std::size_t bytes{0};
    std::size_t calls{0};
};

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

bool collect_fragment(void* opaque, std::span<const std::byte> packet) noexcept {
    auto& log = *static_cast<FragmentLog*>(opaque);
    if (log.count >= log.packets.size() || packet.size() > log.packets[0].size()) {
        return false;
    }
    std::copy(packet.begin(), packet.end(), log.packets[log.count].begin());
    log.bytes[log.count] = packet.size();
    ++log.count;
    return true;
}

bool deliver_datagram(
    void* opaque,
    const vectornet::net::ReassemblyKey& key,
    std::span<const std::byte> payload) noexcept {
    auto& delivery = *static_cast<Delivery*>(opaque);
    if (payload.size() > delivery.payload.size()) {
        return false;
    }
    delivery.key = key;
    delivery.bytes = payload.size();
    ++delivery.calls;
    std::copy(payload.begin(), payload.end(), delivery.payload.begin());
    return true;
}

[[nodiscard]] vectornet::net::Ipv4Header base_header(std::uint16_t id = 0x1234) {
    return {
        .identification = id,
        .ttl = vectornet::net::kVectorNetTtl,
        .protocol = vectornet::net::kVectorNetProtocol,
        .source = 0xC6130001U,
        .destination = 0xC6130002U,
    };
}

[[nodiscard]] bool make_fragments(
    std::array<std::byte, 4'000>& payload,
    FragmentLog& log) {
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>(index & 0xFFU);
    }
    std::array<std::byte, 1'500> scratch{};
    return vectornet::net::fragment_ipv4_payload(
               base_header(),
               payload,
               1'500,
               scratch,
               &collect_fragment,
               &log) == Ipv4Status::ok &&
           log.count == 3;
}

[[nodiscard]] bool insert_packet(
    vectornet::net::ReassemblyTable& table,
    const FragmentLog& log,
    std::size_t index,
    std::uint64_t now,
    Delivery& delivery,
    ReassemblyStatus expected) {
    vectornet::net::Ipv4PacketView packet{};
    if (!expect(
            vectornet::net::parse_ipv4_packet(
                std::span<const std::byte>(
                    log.packets[index].data(), log.bytes[index]),
                packet) == Ipv4Status::ok,
            "fragment parse failed")) {
        return false;
    }
    return expect(
        table.insert(
            packet.header,
            packet.payload,
            now,
            &deliver_datagram,
            &delivery) == expected,
        "unexpected reassembly insert status");
}

[[nodiscard]] bool test_out_of_order_completion() {
    std::array<std::byte, 4'000> payload{};
    FragmentLog log{};
    if (!expect(make_fragments(payload, log), "fragment fixture creation failed")) {
        return false;
    }
    vectornet::net::ReassemblyTable table(2, 100);
    Delivery delivery{};
    if (!insert_packet(table, log, 2, 0, delivery, ReassemblyStatus::pending) ||
        !insert_packet(table, log, 0, 1, delivery, ReassemblyStatus::pending) ||
        !insert_packet(table, log, 1, 2, delivery, ReassemblyStatus::complete)) {
        return false;
    }
    return expect(delivery.calls == 1, "completed datagram delivery count mismatch") &&
           expect(delivery.bytes == payload.size(), "completed payload size mismatch") &&
           expect(std::equal(payload.begin(), payload.end(), delivery.payload.begin()),
                  "out-of-order reassembly corrupted payload") &&
           expect(delivery.key.identification == 0x1234, "reassembly key mismatch") &&
           expect(table.active_slots() == 0, "completed slot not released") &&
           expect(table.statistics().completed == 1, "completion statistic mismatch");
}

[[nodiscard]] bool test_timeout_and_capacity() {
    std::array<std::byte, 4'000> payload{};
    FragmentLog log{};
    if (!make_fragments(payload, log)) {
        return false;
    }
    vectornet::net::Ipv4PacketView first{};
    if (vectornet::net::parse_ipv4_packet(
            std::span<const std::byte>(log.packets[0].data(), log.bytes[0]),
            first) != Ipv4Status::ok) {
        return false;
    }
    vectornet::net::ReassemblyTable table(1, 100);
    Delivery delivery{};
    if (!expect(
            table.insert(first.header, first.payload, 10, &deliver_datagram, &delivery) ==
                ReassemblyStatus::pending,
            "timeout fixture insert failed") ||
        !expect(table.sweep(109) == 0, "slot expired before timeout") ||
        !expect(table.sweep(110) == 1, "slot did not expire at timeout") ||
        !expect(table.active_slots() == 0, "expired slot retained") ||
        !expect(table.statistics().timed_out == 1, "timeout statistic mismatch")) {
        return false;
    }

    auto second_header = first.header;
    second_header.identification = 0x4321;
    if (!expect(
            table.insert(first.header, first.payload, 200, &deliver_datagram, &delivery) ==
                ReassemblyStatus::pending,
            "capacity fixture insert failed") ||
        !expect(
            table.insert(
                second_header, first.payload, 201, &deliver_datagram, &delivery) ==
                ReassemblyStatus::table_full,
            "full reassembly table accepted another key")) {
        return false;
    }
    return expect(table.statistics().table_full == 1, "table-full statistic mismatch");
}

[[nodiscard]] bool test_malformed_and_unfragmented() {
    vectornet::net::ReassemblyTable table(1, 100);
    Delivery delivery{};
    auto malformed = base_header();
    malformed.flags_fragment_offset = vectornet::net::kIpv4FlagMoreFragments;
    std::array<std::byte, 7> seven{};
    if (!expect(
            table.insert(malformed, seven, 0, &deliver_datagram, &delivery) ==
                ReassemblyStatus::malformed,
            "unaligned non-final fragment accepted")) {
        return false;
    }
    auto whole = base_header(7);
    std::array<std::byte, 3> payload{
        std::byte{1}, std::byte{2}, std::byte{3}};
    return expect(
               table.insert(whole, payload, 1, &deliver_datagram, &delivery) ==
                   ReassemblyStatus::complete,
               "unfragmented datagram not delivered") &&
           expect(delivery.calls == 1 && delivery.bytes == payload.size(),
                  "unfragmented delivery mismatch");
}

[[nodiscard]] bool test_first_arrival_wins_overlap() {
    vectornet::net::ReassemblyTable table(1, 100);
    Delivery delivery{};
    auto first = base_header(0x7777);
    first.flags_fragment_offset = vectornet::net::kIpv4FlagMoreFragments;
    std::array<std::byte, 16> first_payload{};
    for (std::size_t index = 0; index < first_payload.size(); ++index) {
        first_payload[index] = static_cast<std::byte>(index);
    }
    if (!expect(
            table.insert(first, first_payload, 0, &deliver_datagram, &delivery) ==
                ReassemblyStatus::pending,
            "first overlap fragment rejected") ||
        !expect(
            table.insert(first, first_payload, 1, &deliver_datagram, &delivery) ==
                ReassemblyStatus::pending,
            "duplicate fragment changed state")) {
        return false;
    }

    auto final = base_header(0x7777);
    final.flags_fragment_offset = 1;
    std::array<std::byte, 16> final_payload{};
    std::fill(final_payload.begin(), final_payload.begin() + 8, std::byte{0xEE});
    for (std::size_t index = 8; index < final_payload.size(); ++index) {
        final_payload[index] = static_cast<std::byte>(index + 8);
    }
    if (!expect(
            table.insert(final, final_payload, 2, &deliver_datagram, &delivery) ==
                ReassemblyStatus::complete,
            "overlapping final fragment did not complete") ||
        !expect(delivery.bytes == 24, "overlap result size mismatch")) {
        return false;
    }
    for (std::size_t index = 0; index < delivery.bytes; ++index) {
        if (!expect(
                delivery.payload[index] == static_cast<std::byte>(index),
                "later overlap overwrote first-arrival byte")) {
            return false;
        }
    }
    const auto stats = table.statistics();
    return expect(stats.duplicate_fragments == 1, "duplicate counter mismatch") &&
           expect(stats.overlap_bytes_ignored == 24, "ignored-overlap counter mismatch");
}

}  // namespace

int main() {
    return test_out_of_order_completion() && test_timeout_and_capacity() &&
                   test_malformed_and_unfragmented() &&
                   test_first_arrival_wins_overlap()
               ? 0
               : 1;
}

#include "vectornet/transport/connection.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <system_error>

namespace {

using vectornet::transport::Connection;
using vectornet::transport::ConnectionError;
using vectornet::transport::ConnectionState;
using vectornet::transport::TransmitReason;

struct EndpointContext {
    Connection* peer{nullptr};
    std::uint64_t now_ns{1};
    std::array<std::byte, 1'436> received{};
    std::size_t received_bytes{0};
    std::size_t errors{0};
    bool drop_next_data{false};
};

[[nodiscard]] std::error_code transmit(
    void* opaque,
    std::span<const std::byte> segment,
    TransmitReason reason) noexcept {
    auto& context = *static_cast<EndpointContext*>(opaque);
    if (context.drop_next_data && reason == TransmitReason::new_data) {
        context.drop_next_data = false;
        return {};
    }
    if (context.peer == nullptr ||
        !context.peer->on_segment(segment, context.now_ns)) {
        return std::make_error_code(std::errc::protocol_error);
    }
    return {};
}

void receive(
    void* opaque,
    std::span<const std::byte> payload) noexcept {
    auto& context = *static_cast<EndpointContext*>(opaque);
    if (payload.size() > context.received.size()) {
        ++context.errors;
        return;
    }
    std::copy(payload.begin(), payload.end(), context.received.begin());
    context.received_bytes = payload.size();
}

void error(void* opaque, ConnectionError) noexcept {
    ++static_cast<EndpointContext*>(opaque)->errors;
}

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

}  // namespace

int main() {
    using namespace vectornet::transport;
    EndpointContext client_context{};
    EndpointContext server_context{};
    const ConnectionConfig config{
        .maximum_segment_payload_bytes = 1'200,
        .packet_pool_buffers = 64,
        .retransmission_capacity = 32,
        .receive_capacity = 32,
    };
    Connection client(config, {
        .transmit = &transmit,
        .transmit_context = &client_context,
        .receive = &receive,
        .receive_context = &client_context,
        .error = &error,
        .error_context = &client_context,
    });
    Connection server(config, {
        .transmit = &transmit,
        .transmit_context = &server_context,
        .receive = &receive,
        .receive_context = &server_context,
        .error = &error,
        .error_context = &server_context,
    });
    client_context.peer = &server;
    server_context.peer = &client;

    if (!expect(client.connect(1), "connect failed") ||
        !expect(client.state() == ConnectionState::established,
                "client handshake incomplete") ||
        !expect(server.state() == ConnectionState::established,
                "server handshake incomplete")) {
        return 1;
    }

    constexpr std::array<std::byte, 5> first{
        std::byte{'h'}, std::byte{'e'}, std::byte{'l'},
        std::byte{'l'}, std::byte{'o'},
    };
    client_context.now_ns = 10;
    server_context.now_ns = 10;
    if (!expect(client.send(first, 10) == SendStatus::accepted,
                "first send rejected") ||
        !expect(server_context.received_bytes == first.size(),
                "first payload not delivered") ||
        !expect(std::equal(
                    first.begin(), first.end(), server_context.received.begin()),
                "first payload changed") ||
        !expect(client.statistics().payload_bytes_acked == first.size(),
                "first payload not acknowledged")) {
        return 1;
    }

    constexpr std::array<std::byte, 4> lost{
        std::byte{'l'}, std::byte{'o'}, std::byte{'s'}, std::byte{'t'},
    };
    server_context.received_bytes = 0;
    client_context.drop_next_data = true;
    client_context.now_ns = 20;
    if (!expect(client.send(lost, 20) == SendStatus::accepted,
                "loss-injection send rejected") ||
        !expect(server_context.received_bytes == 0,
                "dropped payload arrived")) {
        return 1;
    }
    const std::uint64_t timeout = 20 + client.retransmission_timeout_ns();
    client_context.now_ns = timeout;
    server_context.now_ns = timeout;
    client.tick(timeout);
    const auto statistics = client.statistics();
    if (!expect(server_context.received_bytes == lost.size(),
                "RTO did not deliver missing payload") ||
        !expect(statistics.rto_retransmissions == 1,
                "RTO retransmission not counted") ||
        !expect(statistics.payload_bytes_acked == first.size() + lost.size(),
                "retransmitted payload not acknowledged") ||
        !expect(client_context.errors == 0 && server_context.errors == 0,
                "connection callback reported error")) {
        return 1;
    }

    std::array<std::byte, 1'201> oversized{};
    return expect(
               client.send(oversized, timeout + 1) ==
                   SendStatus::payload_too_large,
               "oversized payload accepted")
        ? 0
        : 1;
}

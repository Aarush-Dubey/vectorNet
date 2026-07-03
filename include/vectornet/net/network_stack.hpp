#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <system_error>

#include "vectornet/link/arp.hpp"
#include "vectornet/link/link_endpoint.hpp"
#include "vectornet/net/ipv4.hpp"

namespace vectornet::net {

struct NetworkStackConfig {
    std::string interface_name;
    Ipv4Address local_address{0};
    std::size_t requested_bpf_buffer_bytes{0};
    bool promiscuous{false};
    link::ArpResolverConfig arp{};
};

enum class NetworkStatus : std::uint8_t {
    accepted,
    queued_for_arp,
    would_block,
    payload_too_large,
    unreachable,
    malformed,
    send_failed,
};

struct NetworkStackStatistics {
    std::uint64_t ipv4_received{0};
    std::uint64_t ipv4_delivered{0};
    std::uint64_t malformed_drops{0};
    std::uint64_t wrong_destination_drops{0};
    std::uint64_t wrong_protocol_drops{0};
    std::uint64_t reassembly_drops{0};
    std::uint64_t arp_unreachable{0};
};

using DatagramCallback = void (*)(
    void* context,
    Ipv4Address source,
    std::span<const std::byte> payload,
    const link::CaptureMetadata& metadata) noexcept;

class NetworkStack final {
public:
    NetworkStack(const NetworkStack&) = delete;
    NetworkStack& operator=(const NetworkStack&) = delete;
    NetworkStack(NetworkStack&&) noexcept;
    NetworkStack& operator=(NetworkStack&&) noexcept;
    ~NetworkStack();

    [[nodiscard]] static std::unique_ptr<NetworkStack> open(
        const NetworkStackConfig& config,
        std::error_code& error);

    [[nodiscard]] NetworkStatus send_datagram(
        Ipv4Address destination,
        std::span<const std::byte> payload,
        std::uint64_t now_ns) noexcept;

    [[nodiscard]] std::error_code poll_datagrams(
        DatagramCallback callback,
        void* context) noexcept;

    [[nodiscard]] std::error_code poll_datagrams_for(
        DatagramCallback callback,
        void* context,
        std::uint32_t timeout_ms) noexcept;

    void tick(std::uint64_t now_ns) noexcept;

    [[nodiscard]] link::InterfaceInfo interface_info() const noexcept;
    [[nodiscard]] link::BpfStatistics bpf_statistics(
        std::error_code& error) const noexcept;
    [[nodiscard]] NetworkStackStatistics statistics() const noexcept;

private:
    struct Impl;

    explicit NetworkStack(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

}  // namespace vectornet::net

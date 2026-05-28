#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <system_error>
#include <vector>

#include "vectornet/link/ethernet.hpp"

namespace vectornet::link {

using Ipv4Address = std::uint32_t;

inline constexpr std::size_t kArpPayloadBytes = 28;
inline constexpr std::uint64_t kArpDefaultTtlNs = 60'000'000'000ULL;
inline constexpr MacAddress kEthernetBroadcast{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

enum class ArpOperation : std::uint16_t {
    request = 1,
    reply = 2,
};

struct ArpMessage {
    ArpOperation operation{ArpOperation::request};
    MacAddress sender_hardware{};
    Ipv4Address sender_protocol{0};
    MacAddress target_hardware{};
    Ipv4Address target_protocol{0};
};

enum class ArpStatus : std::uint8_t {
    ok,
    pending,
    malformed,
    unsupported,
    output_too_small,
    cache_full,
    send_failed,
};

[[nodiscard]] ArpStatus parse_arp_message(
    std::span<const std::byte> payload,
    ArpMessage& message) noexcept;

[[nodiscard]] ArpStatus build_arp_message(
    const ArpMessage& message,
    std::span<std::byte> output,
    std::size_t& bytes_written) noexcept;

class ArpCache final {
public:
    explicit ArpCache(
        std::size_t capacity,
        std::uint64_t ttl_ns = kArpDefaultTtlNs);

    [[nodiscard]] std::optional<MacAddress> lookup(
        Ipv4Address address,
        std::uint64_t now_ns) noexcept;

    [[nodiscard]] bool insert(
        Ipv4Address address,
        const MacAddress& hardware,
        std::uint64_t now_ns) noexcept;

    [[nodiscard]] std::size_t capacity() const noexcept;
    [[nodiscard]] std::size_t active_entries(std::uint64_t now_ns) noexcept;

private:
    struct Entry {
        Ipv4Address address{0};
        MacAddress hardware{};
        std::uint64_t expires_at_ns{0};
        bool valid{false};
    };

    void expire(std::uint64_t now_ns) noexcept;
    [[nodiscard]] std::uint64_t expiration_from(std::uint64_t now_ns) const noexcept;

    std::vector<Entry> entries_;
    std::uint64_t ttl_ns_;
};

using ArpTransmitCallback = std::error_code (*)(
    void* context,
    const MacAddress& destination,
    std::span<const std::byte> arp_payload) noexcept;

struct ArpResolveResult {
    std::optional<MacAddress> hardware{};
    ArpStatus status{ArpStatus::pending};
};

class ArpResolver final {
public:
    ArpResolver(
        Ipv4Address local_protocol,
        const MacAddress& local_hardware,
        std::size_t cache_capacity,
        ArpTransmitCallback transmit,
        void* transmit_context,
        std::uint64_t ttl_ns = kArpDefaultTtlNs);

    [[nodiscard]] ArpResolveResult resolve(
        Ipv4Address target,
        std::uint64_t now_ns) noexcept;

    [[nodiscard]] ArpStatus on_arp_payload(
        std::span<const std::byte> payload,
        std::uint64_t now_ns) noexcept;

    [[nodiscard]] ArpCache& cache() noexcept;
    [[nodiscard]] const ArpCache& cache() const noexcept;

private:
    [[nodiscard]] ArpStatus transmit_message(
        const MacAddress& destination,
        const ArpMessage& message) noexcept;

    Ipv4Address local_protocol_;
    MacAddress local_hardware_;
    ArpCache cache_;
    ArpTransmitCallback transmit_;
    void* transmit_context_;
};

}  // namespace vectornet::link

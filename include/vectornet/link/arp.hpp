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
inline constexpr std::size_t kArpMaximumPendingPayloadBytes = 2'048;
inline constexpr std::uint64_t kArpDefaultTtlNs = 60'000'000'000ULL;
inline constexpr std::uint64_t kArpDefaultRefreshMarginNs = 5'000'000'000ULL;
inline constexpr std::uint64_t kArpDefaultRetryIntervalNs = 250'000'000ULL;
inline constexpr std::uint64_t kArpDefaultPendingDeadlineNs = 1'000'000'000ULL;
inline constexpr std::uint8_t kArpDefaultMaximumAttempts = 3;
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
    queued,
    queue_full,
    payload_too_large,
    unreachable,
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
    friend class ArpResolver;

    struct Entry {
        Ipv4Address address{0};
        MacAddress hardware{};
        std::uint64_t expires_at_ns{0};
        bool valid{false};
        bool refresh_requested{false};
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

using ArpFrameTransmitCallback = std::error_code (*)(
    void* context,
    const MacAddress& destination,
    std::uint16_t ether_type,
    std::span<const std::byte> payload) noexcept;

using ArpFailureCallback = void (*)(
    void* context,
    Ipv4Address target,
    ArpStatus reason) noexcept;

struct ArpResolverConfig {
    std::size_t cache_capacity{64};
    std::size_t pending_capacity{64};
    std::uint64_t ttl_ns{kArpDefaultTtlNs};
    std::uint64_t refresh_margin_ns{kArpDefaultRefreshMarginNs};
    std::uint64_t retry_interval_ns{kArpDefaultRetryIntervalNs};
    std::uint64_t pending_deadline_ns{kArpDefaultPendingDeadlineNs};
    std::uint8_t maximum_attempts{kArpDefaultMaximumAttempts};
};

struct ArpResolverCallbacks {
    ArpTransmitCallback arp_transmit{nullptr};
    void* arp_context{nullptr};
    ArpFrameTransmitCallback frame_transmit{nullptr};
    void* frame_context{nullptr};
    ArpFailureCallback failure{nullptr};
    void* failure_context{nullptr};
};

struct ArpResolveResult {
    std::optional<MacAddress> hardware{};
    ArpStatus status{ArpStatus::pending};
};

class ArpResolver final {
public:
    ArpResolver(
        Ipv4Address local_protocol,
        const MacAddress& local_hardware,
        const ArpResolverConfig& config,
        const ArpResolverCallbacks& callbacks);

    [[nodiscard]] ArpResolveResult resolve(
        Ipv4Address target,
        std::uint64_t now_ns) noexcept;

    [[nodiscard]] ArpStatus on_arp_payload(
        std::span<const std::byte> payload,
        std::uint64_t now_ns) noexcept;

    [[nodiscard]] ArpStatus queue_frame(
        Ipv4Address target,
        std::uint16_t ether_type,
        std::span<const std::byte> payload,
        std::uint64_t now_ns) noexcept;

    void tick(std::uint64_t now_ns) noexcept;

    [[nodiscard]] std::size_t pending_frames() const noexcept;
    [[nodiscard]] std::size_t active_resolutions() const noexcept;

    [[nodiscard]] ArpCache& cache() noexcept;
    [[nodiscard]] const ArpCache& cache() const noexcept;

private:
    struct PendingFrame {
        Ipv4Address target{0};
        std::uint16_t ether_type{0};
        std::size_t payload_bytes{0};
        std::uint64_t deadline_ns{0};
        std::array<std::byte, kArpMaximumPendingPayloadBytes> payload{};
        bool active{false};
    };

    struct Resolution {
        Ipv4Address target{0};
        std::uint64_t next_retry_ns{0};
        std::uint64_t deadline_ns{0};
        std::uint8_t attempts{0};
        bool active{false};
    };

    [[nodiscard]] ArpStatus transmit_message(
        const MacAddress& destination,
        const ArpMessage& message) noexcept;

    [[nodiscard]] ArpStatus ensure_resolution(
        Ipv4Address target,
        std::uint64_t now_ns) noexcept;

    [[nodiscard]] ArpStatus send_request(Ipv4Address target) noexcept;
    [[nodiscard]] ArpStatus flush_pending(
        Ipv4Address target,
        const MacAddress& hardware) noexcept;
    void fail_pending(Ipv4Address target, ArpStatus reason) noexcept;
    void clear_resolution(Ipv4Address target) noexcept;
    [[nodiscard]] std::uint64_t deadline_from(
        std::uint64_t now_ns,
        std::uint64_t interval_ns) const noexcept;

    Ipv4Address local_protocol_;
    MacAddress local_hardware_;
    ArpCache cache_;
    ArpResolverConfig config_;
    ArpResolverCallbacks callbacks_;
    std::vector<PendingFrame> pending_;
    std::vector<Resolution> resolutions_;
};

}  // namespace vectornet::link

#include "vectornet/link/arp.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace vectornet::link {
namespace {

constexpr std::uint16_t kHardwareEthernet = 1;
constexpr std::uint16_t kProtocolIpv4 = kEtherTypeIpv4;
constexpr std::uint8_t kHardwareBytes = 6;
constexpr std::uint8_t kProtocolBytes = 4;

[[nodiscard]] std::uint16_t read_be16(const std::byte* bytes) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[0])) << 8U |
        std::to_integer<std::uint8_t>(bytes[1]));
}

[[nodiscard]] std::uint32_t read_be32(const std::byte* bytes) noexcept {
    return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[0])) << 24U |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[1])) << 16U |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) << 8U |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3]));
}

void write_be16(std::byte* bytes, std::uint16_t value) noexcept {
    bytes[0] = static_cast<std::byte>((value >> 8U) & 0xFFU);
    bytes[1] = static_cast<std::byte>(value & 0xFFU);
}

void write_be32(std::byte* bytes, std::uint32_t value) noexcept {
    bytes[0] = static_cast<std::byte>((value >> 24U) & 0xFFU);
    bytes[1] = static_cast<std::byte>((value >> 16U) & 0xFFU);
    bytes[2] = static_cast<std::byte>((value >> 8U) & 0xFFU);
    bytes[3] = static_cast<std::byte>(value & 0xFFU);
}

void write_mac(std::byte* output, const MacAddress& hardware) noexcept {
    for (std::size_t index = 0; index < hardware.size(); ++index) {
        output[index] = static_cast<std::byte>(hardware[index]);
    }
}

void read_mac(const std::byte* input, MacAddress& hardware) noexcept {
    for (std::size_t index = 0; index < hardware.size(); ++index) {
        hardware[index] = std::to_integer<std::uint8_t>(input[index]);
    }
}

}  // namespace

ArpStatus parse_arp_message(
    std::span<const std::byte> payload,
    ArpMessage& message) noexcept {
    message = {};
    if (payload.size() < kArpPayloadBytes) {
        return ArpStatus::malformed;
    }
    if (read_be16(payload.data()) != kHardwareEthernet ||
        read_be16(payload.data() + 2) != kProtocolIpv4 ||
        std::to_integer<std::uint8_t>(payload[4]) != kHardwareBytes ||
        std::to_integer<std::uint8_t>(payload[5]) != kProtocolBytes) {
        return ArpStatus::unsupported;
    }

    const std::uint16_t operation = read_be16(payload.data() + 6);
    if (operation != static_cast<std::uint16_t>(ArpOperation::request) &&
        operation != static_cast<std::uint16_t>(ArpOperation::reply)) {
        return ArpStatus::unsupported;
    }
    message.operation = static_cast<ArpOperation>(operation);
    read_mac(payload.data() + 8, message.sender_hardware);
    message.sender_protocol = read_be32(payload.data() + 14);
    read_mac(payload.data() + 18, message.target_hardware);
    message.target_protocol = read_be32(payload.data() + 24);
    return ArpStatus::ok;
}

ArpStatus build_arp_message(
    const ArpMessage& message,
    std::span<std::byte> output,
    std::size_t& bytes_written) noexcept {
    bytes_written = 0;
    if (output.size() < kArpPayloadBytes) {
        return ArpStatus::output_too_small;
    }
    if (message.operation != ArpOperation::request &&
        message.operation != ArpOperation::reply) {
        return ArpStatus::unsupported;
    }

    write_be16(output.data(), kHardwareEthernet);
    write_be16(output.data() + 2, kProtocolIpv4);
    output[4] = static_cast<std::byte>(kHardwareBytes);
    output[5] = static_cast<std::byte>(kProtocolBytes);
    write_be16(output.data() + 6, static_cast<std::uint16_t>(message.operation));
    write_mac(output.data() + 8, message.sender_hardware);
    write_be32(output.data() + 14, message.sender_protocol);
    write_mac(output.data() + 18, message.target_hardware);
    write_be32(output.data() + 24, message.target_protocol);
    bytes_written = kArpPayloadBytes;
    return ArpStatus::ok;
}

ArpCache::ArpCache(std::size_t capacity, std::uint64_t ttl_ns)
    : entries_(capacity), ttl_ns_(ttl_ns) {}

std::optional<MacAddress> ArpCache::lookup(
    Ipv4Address address,
    std::uint64_t now_ns) noexcept {
    for (auto& entry : entries_) {
        if (!entry.valid || entry.address != address) {
            continue;
        }
        if (now_ns >= entry.expires_at_ns) {
            entry.valid = false;
            return std::nullopt;
        }
        return entry.hardware;
    }
    return std::nullopt;
}

bool ArpCache::insert(
    Ipv4Address address,
    const MacAddress& hardware,
    std::uint64_t now_ns) noexcept {
    expire(now_ns);
    Entry* available = nullptr;
    for (auto& entry : entries_) {
        if (entry.valid && entry.address == address) {
            available = &entry;
            break;
        }
        if (!entry.valid && available == nullptr) {
            available = &entry;
        }
    }
    if (available == nullptr) {
        return false;
    }
    *available = Entry{
        .address = address,
        .hardware = hardware,
        .expires_at_ns = expiration_from(now_ns),
        .valid = true,
        .refresh_requested = false,
    };
    return true;
}

std::size_t ArpCache::capacity() const noexcept {
    return entries_.size();
}

std::size_t ArpCache::active_entries(std::uint64_t now_ns) noexcept {
    expire(now_ns);
    return static_cast<std::size_t>(std::count_if(
        entries_.begin(), entries_.end(), [](const Entry& entry) { return entry.valid; }));
}

void ArpCache::expire(std::uint64_t now_ns) noexcept {
    for (auto& entry : entries_) {
        if (entry.valid && now_ns >= entry.expires_at_ns) {
            entry.valid = false;
        }
    }
}

std::uint64_t ArpCache::expiration_from(std::uint64_t now_ns) const noexcept {
    if (ttl_ns_ > std::numeric_limits<std::uint64_t>::max() - now_ns) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return now_ns + ttl_ns_;
}

ArpResolver::ArpResolver(
    Ipv4Address local_protocol,
    const MacAddress& local_hardware,
    const ArpResolverConfig& config,
    const ArpResolverCallbacks& callbacks)
    : local_protocol_(local_protocol),
      local_hardware_(local_hardware),
      cache_(config.cache_capacity, config.ttl_ns),
      config_(config),
      callbacks_(callbacks),
      pending_(config.pending_capacity),
      resolutions_(std::max(config.cache_capacity, config.pending_capacity)) {}

ArpResolveResult ArpResolver::resolve(
    Ipv4Address target,
    std::uint64_t now_ns) noexcept {
    if (auto hardware = cache_.lookup(target, now_ns); hardware.has_value()) {
        return {.hardware = hardware, .status = ArpStatus::ok};
    }

    const ArpStatus status = ensure_resolution(target, now_ns);
    return {
        .hardware = std::nullopt,
        .status = status,
    };
}

ArpStatus ArpResolver::on_arp_payload(
    std::span<const std::byte> payload,
    std::uint64_t now_ns) noexcept {
    ArpMessage message{};
    const ArpStatus parse_status = parse_arp_message(payload, message);
    if (parse_status != ArpStatus::ok) {
        return parse_status;
    }
    const bool cached = cache_.insert(
        message.sender_protocol, message.sender_hardware, now_ns);
    clear_resolution(message.sender_protocol);
    const ArpStatus flush_status =
        flush_pending(message.sender_protocol, message.sender_hardware);

    ArpStatus reply_status = ArpStatus::ok;
    if (message.operation == ArpOperation::request &&
        message.target_protocol == local_protocol_) {
        const ArpMessage reply{
            .operation = ArpOperation::reply,
            .sender_hardware = local_hardware_,
            .sender_protocol = local_protocol_,
            .target_hardware = message.sender_hardware,
            .target_protocol = message.sender_protocol,
        };
        reply_status = transmit_message(message.sender_hardware, reply);
    }
    if (flush_status != ArpStatus::ok) {
        return flush_status;
    }
    if (reply_status != ArpStatus::ok) {
        return reply_status;
    }
    return cached ? ArpStatus::ok : ArpStatus::cache_full;
}

ArpStatus ArpResolver::queue_frame(
    Ipv4Address target,
    std::uint16_t ether_type,
    std::span<const std::byte> payload,
    std::uint64_t now_ns) noexcept {
    if (payload.size() > kArpMaximumPendingPayloadBytes) {
        return ArpStatus::payload_too_large;
    }
    if (callbacks_.frame_transmit == nullptr) {
        return ArpStatus::send_failed;
    }
    if (auto hardware = cache_.lookup(target, now_ns); hardware.has_value()) {
        const std::error_code error = callbacks_.frame_transmit(
            callbacks_.frame_context, *hardware, ether_type, payload);
        return error ? ArpStatus::send_failed : ArpStatus::ok;
    }

    PendingFrame* slot = nullptr;
    for (auto& pending : pending_) {
        if (!pending.active) {
            slot = &pending;
            break;
        }
    }
    if (slot == nullptr) {
        return ArpStatus::queue_full;
    }
    slot->target = target;
    slot->ether_type = ether_type;
    slot->payload_bytes = payload.size();
    slot->deadline_ns = deadline_from(now_ns, config_.pending_deadline_ns);
    slot->active = true;
    std::copy(payload.begin(), payload.end(), slot->payload.begin());
    const ArpStatus resolution_status = ensure_resolution(target, now_ns);
    if (resolution_status != ArpStatus::pending) {
        slot->active = false;
        return resolution_status;
    }
    return ArpStatus::queued;
}

void ArpResolver::tick(std::uint64_t now_ns) noexcept {
    cache_.expire(now_ns);
    for (auto& pending : pending_) {
        if (!pending.active || now_ns < pending.deadline_ns) {
            continue;
        }
        if (callbacks_.failure != nullptr) {
            callbacks_.failure(
                callbacks_.failure_context, pending.target, ArpStatus::unreachable);
        }
        pending.active = false;
    }

    for (auto& resolution : resolutions_) {
        if (!resolution.active) {
            continue;
        }
        if (now_ns >= resolution.deadline_ns) {
            fail_pending(resolution.target, ArpStatus::unreachable);
            resolution.active = false;
            continue;
        }
        if (resolution.attempts >= config_.maximum_attempts ||
            now_ns < resolution.next_retry_ns) {
            continue;
        }
        const ArpStatus status = send_request(resolution.target);
        if (status != ArpStatus::ok) {
            fail_pending(resolution.target, status);
            resolution.active = false;
            continue;
        }
        ++resolution.attempts;
        resolution.next_retry_ns =
            deadline_from(now_ns, config_.retry_interval_ns);
    }

    for (auto& entry : cache_.entries_) {
        if (!entry.valid || entry.refresh_requested || now_ns >= entry.expires_at_ns ||
            entry.expires_at_ns - now_ns > config_.refresh_margin_ns) {
            continue;
        }
        if (ensure_resolution(entry.address, now_ns) == ArpStatus::pending) {
            entry.refresh_requested = true;
        }
    }
}

std::size_t ArpResolver::pending_frames() const noexcept {
    return static_cast<std::size_t>(std::count_if(
        pending_.begin(), pending_.end(),
        [](const PendingFrame& pending) { return pending.active; }));
}

std::size_t ArpResolver::active_resolutions() const noexcept {
    return static_cast<std::size_t>(std::count_if(
        resolutions_.begin(), resolutions_.end(),
        [](const Resolution& resolution) { return resolution.active; }));
}

ArpCache& ArpResolver::cache() noexcept {
    return cache_;
}

const ArpCache& ArpResolver::cache() const noexcept {
    return cache_;
}

ArpStatus ArpResolver::transmit_message(
    const MacAddress& destination,
    const ArpMessage& message) noexcept {
    if (callbacks_.arp_transmit == nullptr) {
        return ArpStatus::send_failed;
    }
    std::array<std::byte, kArpPayloadBytes> payload{};
    std::size_t bytes_written = 0;
    const ArpStatus build_status = build_arp_message(message, payload, bytes_written);
    if (build_status != ArpStatus::ok) {
        return build_status;
    }
    const std::error_code error = callbacks_.arp_transmit(
        callbacks_.arp_context,
        destination,
        std::span<const std::byte>(payload.data(), bytes_written));
    return error ? ArpStatus::send_failed : ArpStatus::ok;
}

ArpStatus ArpResolver::ensure_resolution(
    Ipv4Address target,
    std::uint64_t now_ns) noexcept {
    if (config_.maximum_attempts == 0) {
        return ArpStatus::send_failed;
    }
    for (const auto& resolution : resolutions_) {
        if (resolution.active && resolution.target == target) {
            return ArpStatus::pending;
        }
    }
    Resolution* available = nullptr;
    for (auto& resolution : resolutions_) {
        if (!resolution.active) {
            available = &resolution;
            break;
        }
    }
    if (available == nullptr) {
        return ArpStatus::queue_full;
    }
    *available = Resolution{
        .target = target,
        .next_retry_ns = deadline_from(now_ns, config_.retry_interval_ns),
        .deadline_ns = deadline_from(now_ns, config_.pending_deadline_ns),
        .attempts = 1,
        .active = true,
    };
    const ArpStatus status = send_request(target);
    if (status != ArpStatus::ok) {
        available->active = false;
        return status;
    }
    return ArpStatus::pending;
}

ArpStatus ArpResolver::send_request(Ipv4Address target) noexcept {
    const ArpMessage request{
        .operation = ArpOperation::request,
        .sender_hardware = local_hardware_,
        .sender_protocol = local_protocol_,
        .target_hardware = {},
        .target_protocol = target,
    };
    return transmit_message(kEthernetBroadcast, request);
}

ArpStatus ArpResolver::flush_pending(
    Ipv4Address target,
    const MacAddress& hardware) noexcept {
    ArpStatus result = ArpStatus::ok;
    for (auto& pending : pending_) {
        if (!pending.active || pending.target != target) {
            continue;
        }
        const std::error_code error = callbacks_.frame_transmit == nullptr
            ? std::make_error_code(std::errc::operation_not_supported)
            : callbacks_.frame_transmit(
                  callbacks_.frame_context,
                  hardware,
                  pending.ether_type,
                  std::span<const std::byte>(
                      pending.payload.data(), pending.payload_bytes));
        if (error) {
            result = ArpStatus::send_failed;
            if (callbacks_.failure != nullptr) {
                callbacks_.failure(
                    callbacks_.failure_context, target, ArpStatus::send_failed);
            }
        }
        pending.active = false;
    }
    return result;
}

void ArpResolver::fail_pending(Ipv4Address target, ArpStatus reason) noexcept {
    for (auto& pending : pending_) {
        if (!pending.active || pending.target != target) {
            continue;
        }
        if (callbacks_.failure != nullptr) {
            callbacks_.failure(callbacks_.failure_context, target, reason);
        }
        pending.active = false;
    }
}

void ArpResolver::clear_resolution(Ipv4Address target) noexcept {
    for (auto& resolution : resolutions_) {
        if (resolution.active && resolution.target == target) {
            resolution.active = false;
        }
    }
}

std::uint64_t ArpResolver::deadline_from(
    std::uint64_t now_ns,
    std::uint64_t interval_ns) const noexcept {
    if (interval_ns > std::numeric_limits<std::uint64_t>::max() - now_ns) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return now_ns + interval_ns;
}

}  // namespace vectornet::link

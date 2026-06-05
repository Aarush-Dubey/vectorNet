#include "vectornet/net/ipv4.hpp"

#include <algorithm>

namespace vectornet::net {

Ipv4IdentificationGenerator::Ipv4IdentificationGenerator(
    std::uint16_t initial) noexcept
    : next_(initial) {}

std::uint16_t Ipv4IdentificationGenerator::next() noexcept {
    const std::uint16_t value = next_;
    next_ = static_cast<std::uint16_t>(next_ + 1U);
    return value;
}

Ipv4Status fragment_ipv4_payload(
    const Ipv4Header& header,
    std::span<const std::byte> payload,
    std::size_t mtu,
    std::span<std::byte> scratch,
    Ipv4FragmentCallback callback,
    void* callback_context) noexcept {
    if (callback == nullptr || mtu < kIpv4HeaderBytes || scratch.size() < mtu) {
        return Ipv4Status::invalid_mtu;
    }
    constexpr std::size_t kMaximumPayload = 65'535U - kIpv4HeaderBytes;
    if (payload.size() > kMaximumPayload) {
        return Ipv4Status::payload_too_large;
    }

    const std::size_t mtu_payload = mtu - kIpv4HeaderBytes;
    if (payload.size() <= mtu_payload) {
        Ipv4Header packet_header = header;
        packet_header.flags_fragment_offset = 0;
        std::size_t packet_bytes = 0;
        const Ipv4Status status = build_ipv4_packet(
            packet_header, payload, scratch, packet_bytes);
        if (status != Ipv4Status::ok) {
            return status;
        }
        return callback(
                   callback_context,
                   std::span<const std::byte>(scratch.data(), packet_bytes))
            ? Ipv4Status::ok
            : Ipv4Status::callback_rejected;
    }

    const std::size_t fragment_payload = (mtu_payload / 8U) * 8U;
    if (fragment_payload == 0) {
        return Ipv4Status::invalid_mtu;
    }

    std::size_t offset = 0;
    while (offset < payload.size()) {
        const std::size_t bytes =
            std::min(fragment_payload, payload.size() - offset);
        const bool more = offset + bytes < payload.size();
        const std::size_t offset_units = offset / 8U;
        if (offset_units > kIpv4FragmentOffsetMask) {
            return Ipv4Status::payload_too_large;
        }
        Ipv4Header fragment_header = header;
        fragment_header.flags_fragment_offset = static_cast<std::uint16_t>(
            (more ? kIpv4FlagMoreFragments : 0U) |
            static_cast<std::uint16_t>(offset_units));
        std::size_t packet_bytes = 0;
        const Ipv4Status status = build_ipv4_packet(
            fragment_header,
            payload.subspan(offset, bytes),
            scratch,
            packet_bytes);
        if (status != Ipv4Status::ok) {
            return status;
        }
        if (!callback(
                callback_context,
                std::span<const std::byte>(scratch.data(), packet_bytes))) {
            return Ipv4Status::callback_rejected;
        }
        offset += bytes;
    }
    return Ipv4Status::ok;
}

}  // namespace vectornet::net

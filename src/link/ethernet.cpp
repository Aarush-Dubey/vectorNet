#include "vectornet/link/ethernet.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace vectornet::link {
namespace {

[[nodiscard]] std::uint16_t read_be16(const std::byte* bytes) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[0])) << 8U |
        std::to_integer<std::uint8_t>(bytes[1]));
}

void write_be16(std::byte* bytes, std::uint16_t value) noexcept {
    bytes[0] = static_cast<std::byte>((value >> 8U) & 0xFFU);
    bytes[1] = static_cast<std::byte>(value & 0xFFU);
}

[[nodiscard]] bool is_vlan(std::uint16_t ether_type) noexcept {
    return ether_type == kEtherTypeVlan8021Q || ether_type == kEtherTypeVlan8021Ad;
}

struct DispatchContext {
    EthernetDropCounters* counters;
    EthernetFrameCallback callback;
    void* callback_context;
};

void dispatch_frame(
    void* opaque,
    std::span<const std::byte> frame,
    const CaptureMetadata& metadata) noexcept {
    auto& dispatch = *static_cast<DispatchContext*>(opaque);
    EthernetFrameView parsed{};
    const EthernetStatus status = parse_ethernet_frame(frame, parsed);
    if (status == EthernetStatus::frame_too_short) {
        ++dispatch.counters->short_frames;
        return;
    }
    if (status == EthernetStatus::unsupported_vlan) {
        ++dispatch.counters->vlan_frames;
        return;
    }
    if (status != EthernetStatus::ok) {
        return;
    }
    dispatch.callback(
        dispatch.callback_context,
        parsed.header,
        parsed.payload,
        metadata);
}

}  // namespace

EthernetStatus parse_ethernet_frame(
    std::span<const std::byte> frame,
    EthernetFrameView& result) noexcept {
    result = {};
    if (frame.size() < kEthernetHeaderBytes) {
        return EthernetStatus::frame_too_short;
    }

    std::copy_n(
        reinterpret_cast<const std::uint8_t*>(frame.data()),
        result.header.destination.size(),
        result.header.destination.begin());
    std::copy_n(
        reinterpret_cast<const std::uint8_t*>(frame.data() + 6),
        result.header.source.size(),
        result.header.source.begin());
    result.header.ether_type = read_be16(frame.data() + 12);
    if (is_vlan(result.header.ether_type)) {
        result = {};
        return EthernetStatus::unsupported_vlan;
    }
    result.payload = frame.subspan(kEthernetHeaderBytes);
    return EthernetStatus::ok;
}

EthernetStatus build_ethernet_frame(
    const MacAddress& destination,
    const MacAddress& source,
    std::uint16_t ether_type,
    std::span<const std::byte> payload,
    std::span<std::byte> output,
    std::size_t& frame_bytes) noexcept {
    frame_bytes = 0;
    if (is_vlan(ether_type)) {
        return EthernetStatus::unsupported_vlan;
    }
    if (payload.size() > std::numeric_limits<std::size_t>::max() - kEthernetHeaderBytes) {
        return EthernetStatus::payload_too_large;
    }
    const std::size_t unpadded_bytes = kEthernetHeaderBytes + payload.size();
    const std::size_t required_bytes =
        std::max(unpadded_bytes, kEthernetMinimumFrameBytes);
    if (required_bytes > output.size()) {
        return EthernetStatus::output_too_small;
    }

    for (std::size_t index = 0; index < destination.size(); ++index) {
        output[index] = static_cast<std::byte>(destination[index]);
        output[index + destination.size()] = static_cast<std::byte>(source[index]);
    }
    write_be16(output.data() + 12, ether_type);
    if (!payload.empty()) {
        std::memcpy(output.data() + kEthernetHeaderBytes, payload.data(), payload.size());
    }
    std::fill(output.begin() + static_cast<std::ptrdiff_t>(unpadded_bytes),
              output.begin() + static_cast<std::ptrdiff_t>(required_bytes),
              std::byte{0});
    frame_bytes = required_bytes;
    return EthernetStatus::ok;
}

EthernetEndpoint::EthernetEndpoint(
    std::unique_ptr<LinkEndpoint> link,
    std::unique_ptr<std::byte[]> tx_buffer,
    std::size_t tx_capacity) noexcept
    : link_(std::move(link)),
      tx_buffer_(std::move(tx_buffer)),
      tx_capacity_(tx_capacity) {}

EthernetEndpoint::EthernetEndpoint(EthernetEndpoint&&) noexcept = default;
EthernetEndpoint& EthernetEndpoint::operator=(EthernetEndpoint&&) noexcept = default;
EthernetEndpoint::~EthernetEndpoint() = default;

std::unique_ptr<EthernetEndpoint> EthernetEndpoint::open(
    const LinkConfig& config,
    std::error_code& error) {
    LinkConfig filtered_config = config;
    filtered_config.capture_filter = CaptureFilter::stack_arp_ipv4_253;
    auto link = LinkEndpoint::open(filtered_config, error);
    if (!link) {
        return nullptr;
    }

    const InterfaceInfo info = link->interface_info();
    static_assert(sizeof(std::size_t) > sizeof(info.mtu));
    const std::size_t capacity = std::max(
        static_cast<std::size_t>(info.mtu) + kEthernetHeaderBytes,
        kEthernetMinimumFrameBytes);
    auto tx_buffer = std::make_unique<std::byte[]>(capacity);
    auto endpoint = std::unique_ptr<EthernetEndpoint>(
        new EthernetEndpoint(std::move(link), std::move(tx_buffer), capacity));
    error.clear();
    return endpoint;
}

std::error_code EthernetEndpoint::poll_frames(
    EthernetFrameCallback callback,
    void* context) noexcept {
    if (!link_) {
        return std::make_error_code(std::errc::bad_file_descriptor);
    }
    if (callback == nullptr) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    DispatchContext dispatch{&drop_counters_, callback, context};
    return link_->poll_frames(&dispatch_frame, &dispatch);
}

std::error_code EthernetEndpoint::send_frame(
    const MacAddress& destination,
    std::uint16_t ether_type,
    std::span<const std::byte> payload) noexcept {
    if (!link_ || !tx_buffer_) {
        return std::make_error_code(std::errc::bad_file_descriptor);
    }
    const InterfaceInfo info = link_->interface_info();
    if (payload.size() > info.mtu) {
        return std::make_error_code(std::errc::message_size);
    }
    std::size_t frame_bytes = 0;
    const EthernetStatus status = build_ethernet_frame(
        destination,
        info.mac,
        ether_type,
        payload,
        std::span<std::byte>(tx_buffer_.get(), tx_capacity_),
        frame_bytes);
    if (status == EthernetStatus::unsupported_vlan) {
        return std::make_error_code(std::errc::protocol_not_supported);
    }
    if (status != EthernetStatus::ok) {
        return std::make_error_code(std::errc::message_size);
    }
    return link_->send_frame(
        std::span<const std::byte>(tx_buffer_.get(), frame_bytes));
}

InterfaceInfo EthernetEndpoint::interface_info() const noexcept {
    return link_ ? link_->interface_info() : InterfaceInfo{};
}

EthernetDropCounters EthernetEndpoint::drop_counters() const noexcept {
    return drop_counters_;
}

BpfStatistics EthernetEndpoint::bpf_statistics(std::error_code& error) const noexcept {
    if (!link_) {
        error = std::make_error_code(std::errc::bad_file_descriptor);
        return {};
    }
    return link_->bpf_statistics(error);
}

}  // namespace vectornet::link

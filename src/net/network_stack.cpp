#include "vectornet/net/network_stack.hpp"

#include <algorithm>
#include <ctime>
#include <limits>
#include <utility>

#include "vectornet/link/ethernet.hpp"
#include "vectornet/net/ipv4.hpp"
#include "vectornet/net/reassembly.hpp"

namespace vectornet::net {
namespace {

[[nodiscard]] std::uint64_t monotonic_now_ns() noexcept {
    timespec value{};
    if (::clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0 ||
        value.tv_nsec < 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
           static_cast<std::uint64_t>(value.tv_nsec);
}

[[nodiscard]] NetworkStatus arp_status_to_network(link::ArpStatus status) noexcept {
    switch (status) {
    case link::ArpStatus::ok:
        return NetworkStatus::accepted;
    case link::ArpStatus::queued:
    case link::ArpStatus::pending:
        return NetworkStatus::queued_for_arp;
    case link::ArpStatus::queue_full:
    case link::ArpStatus::cache_full:
        return NetworkStatus::would_block;
    case link::ArpStatus::payload_too_large:
        return NetworkStatus::payload_too_large;
    case link::ArpStatus::unreachable:
        return NetworkStatus::unreachable;
    case link::ArpStatus::malformed:
    case link::ArpStatus::unsupported:
    case link::ArpStatus::output_too_small:
        return NetworkStatus::malformed;
    case link::ArpStatus::send_failed:
        return NetworkStatus::send_failed;
    }
    return NetworkStatus::send_failed;
}

}  // namespace

struct NetworkStack::Impl {
    Impl(
        std::unique_ptr<link::EthernetEndpoint> native_endpoint,
        const NetworkStackConfig& stack_config)
        : endpoint(std::move(native_endpoint)),
          config(stack_config),
          arp(
              config.local_address,
              endpoint->interface_info().mac,
              config.arp,
              link::ArpResolverCallbacks{
                  .arp_transmit = &Impl::transmit_arp,
                  .arp_context = this,
                  .frame_transmit = &Impl::transmit_frame,
                  .frame_context = this,
                  .failure = &Impl::arp_failure,
                  .failure_context = this,
              }),
          fragment_scratch(
              std::make_unique<std::byte[]>(endpoint->interface_info().mtu)) {}

    [[nodiscard]] static std::error_code transmit_arp(
        void* opaque,
        const link::MacAddress& destination,
        std::span<const std::byte> payload) noexcept {
        auto& self = *static_cast<Impl*>(opaque);
        return self.endpoint->send_frame(
            destination, link::kEtherTypeArp, payload);
    }

    [[nodiscard]] static std::error_code transmit_frame(
        void* opaque,
        const link::MacAddress& destination,
        std::uint16_t ether_type,
        std::span<const std::byte> payload) noexcept {
        auto& self = *static_cast<Impl*>(opaque);
        return self.endpoint->send_frame(destination, ether_type, payload);
    }

    static void arp_failure(
        void* opaque,
        link::Ipv4Address,
        link::ArpStatus reason) noexcept {
        auto& self = *static_cast<Impl*>(opaque);
        if (reason == link::ArpStatus::unreachable) {
            ++self.statistics.arp_unreachable;
        }
    }

    [[nodiscard]] static bool emit_fragment(
        void* opaque,
        std::span<const std::byte> packet) noexcept {
        auto& self = *static_cast<Impl*>(opaque);
        const link::ArpStatus status = self.arp.queue_frame(
            self.send_destination,
            link::kEtherTypeIpv4,
            packet,
            self.send_now_ns);
        if (status != link::ArpStatus::ok &&
            status != link::ArpStatus::queued) {
            self.send_status = arp_status_to_network(status);
            return false;
        }
        if (status == link::ArpStatus::queued) {
            self.send_queued = true;
        }
        return true;
    }

    static void receive_frame(
        void* opaque,
        const link::EthernetHeader& header,
        std::span<const std::byte> payload,
        const link::CaptureMetadata& metadata) noexcept {
        auto& self = *static_cast<Impl*>(opaque);
        self.poll_now_ns = monotonic_now_ns();
        if (header.ether_type == link::kEtherTypeArp) {
            const link::ArpStatus status = self.arp.on_arp_payload(
                payload, self.poll_now_ns);
            if (status == link::ArpStatus::malformed ||
                status == link::ArpStatus::unsupported) {
                ++self.statistics.malformed_drops;
            }
            return;
        }
        if (header.ether_type != link::kEtherTypeIpv4) {
            return;
        }
        ++self.statistics.ipv4_received;
        Ipv4PacketView packet{};
        if (parse_ipv4_packet(payload, packet) != Ipv4Status::ok) {
            ++self.statistics.malformed_drops;
            return;
        }
        if (packet.header.destination != self.config.local_address) {
            ++self.statistics.wrong_destination_drops;
            return;
        }
        if (packet.header.protocol != kVectorNetProtocol) {
            ++self.statistics.wrong_protocol_drops;
            return;
        }
        self.current_metadata = metadata;
        const bool fragmented =
            (packet.header.flags_fragment_offset &
             (kIpv4FlagMoreFragments | kIpv4FragmentOffsetMask)) != 0;
        if (!fragmented) {
            self.deliver(packet.header.source, packet.payload);
            return;
        }
        const ReassemblyStatus status = self.reassembly.insert(
            packet.header,
            packet.payload,
            self.poll_now_ns,
            &Impl::reassembly_complete,
            &self);
        if (status == ReassemblyStatus::malformed ||
            status == ReassemblyStatus::table_full ||
            status == ReassemblyStatus::hole_capacity_exhausted ||
            status == ReassemblyStatus::callback_rejected) {
            ++self.statistics.reassembly_drops;
        }
    }

    [[nodiscard]] static bool reassembly_complete(
        void* opaque,
        const ReassemblyKey& key,
        std::span<const std::byte> payload) noexcept {
        auto& self = *static_cast<Impl*>(opaque);
        self.deliver(key.source, payload);
        return true;
    }

    void deliver(Ipv4Address source, std::span<const std::byte> payload) noexcept {
        ++statistics.ipv4_delivered;
        if (datagram_callback != nullptr) {
            datagram_callback(
                datagram_context, source, payload, current_metadata);
        }
    }

    [[nodiscard]] NetworkStatus send_datagram(
        Ipv4Address destination,
        std::span<const std::byte> payload,
        std::uint64_t now_ns) noexcept {
        send_destination = destination;
        send_now_ns = now_ns;
        send_status = NetworkStatus::accepted;
        send_queued = false;
        const Ipv4Header header{
            .identification = identification.next(),
            .ttl = kVectorNetTtl,
            .protocol = kVectorNetProtocol,
            .source = config.local_address,
            .destination = destination,
        };
        const Ipv4Status status = fragment_ipv4_payload(
            header,
            payload,
            endpoint->interface_info().mtu,
            std::span<std::byte>(
                fragment_scratch.get(), endpoint->interface_info().mtu),
            &Impl::emit_fragment,
            this);
        if (status == Ipv4Status::payload_too_large) {
            return NetworkStatus::payload_too_large;
        }
        if (status != Ipv4Status::ok) {
            return send_status == NetworkStatus::accepted
                ? NetworkStatus::send_failed
                : send_status;
        }
        return send_queued ? NetworkStatus::queued_for_arp
                           : NetworkStatus::accepted;
    }

    [[nodiscard]] std::error_code poll(
        DatagramCallback callback,
        void* context,
        const std::uint32_t* timeout_ms) noexcept {
        if (callback == nullptr) {
            return std::make_error_code(std::errc::invalid_argument);
        }
        datagram_callback = callback;
        datagram_context = context;
        poll_now_ns = monotonic_now_ns();
        std::error_code error = timeout_ms == nullptr
            ? endpoint->poll_frames(&Impl::receive_frame, this)
            : endpoint->poll_frames_for(
                  &Impl::receive_frame, this, *timeout_ms);
        datagram_callback = nullptr;
        datagram_context = nullptr;
        return error;
    }

    std::unique_ptr<link::EthernetEndpoint> endpoint;
    NetworkStackConfig config;
    link::ArpResolver arp;
    ReassemblyTable reassembly{};
    Ipv4IdentificationGenerator identification{};
    std::unique_ptr<std::byte[]> fragment_scratch;
    DatagramCallback datagram_callback{nullptr};
    void* datagram_context{nullptr};
    Ipv4Address send_destination{0};
    std::uint64_t send_now_ns{0};
    std::uint64_t poll_now_ns{0};
    NetworkStatus send_status{NetworkStatus::accepted};
    bool send_queued{false};
    link::CaptureMetadata current_metadata{};
    NetworkStackStatistics statistics{};
};

NetworkStack::NetworkStack(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

NetworkStack::NetworkStack(NetworkStack&&) noexcept = default;
NetworkStack& NetworkStack::operator=(NetworkStack&&) noexcept = default;
NetworkStack::~NetworkStack() = default;

std::unique_ptr<NetworkStack> NetworkStack::open(
    const NetworkStackConfig& config,
    std::error_code& error) {
    if (config.interface_name.empty() || config.local_address == 0) {
        error = std::make_error_code(std::errc::invalid_argument);
        return nullptr;
    }
    link::LinkConfig link_config{
        .interface_name = config.interface_name,
        .requested_buffer_bytes = config.requested_bpf_buffer_bytes,
        .promiscuous = config.promiscuous,
        .capture_filter = link::CaptureFilter::stack_arp_ipv4_253,
    };
    auto endpoint = link::EthernetEndpoint::open(link_config, error);
    if (!endpoint) {
        return nullptr;
    }
    auto impl = std::make_unique<Impl>(std::move(endpoint), config);
    error.clear();
    return std::unique_ptr<NetworkStack>(
        new NetworkStack(std::move(impl)));
}

NetworkStatus NetworkStack::send_datagram(
    Ipv4Address destination,
    std::span<const std::byte> payload,
    std::uint64_t now_ns) noexcept {
    return impl_ == nullptr
        ? NetworkStatus::send_failed
        : impl_->send_datagram(destination, payload, now_ns);
}

std::error_code NetworkStack::poll_datagrams(
    DatagramCallback callback,
    void* context) noexcept {
    return impl_ == nullptr
        ? std::make_error_code(std::errc::bad_file_descriptor)
        : impl_->poll(callback, context, nullptr);
}

std::error_code NetworkStack::poll_datagrams_for(
    DatagramCallback callback,
    void* context,
    std::uint32_t timeout_ms) noexcept {
    return impl_ == nullptr
        ? std::make_error_code(std::errc::bad_file_descriptor)
        : impl_->poll(callback, context, &timeout_ms);
}

void NetworkStack::tick(std::uint64_t now_ns) noexcept {
    if (impl_ != nullptr) {
        impl_->arp.tick(now_ns);
        static_cast<void>(impl_->reassembly.sweep(now_ns));
    }
}

link::InterfaceInfo NetworkStack::interface_info() const noexcept {
    return impl_ == nullptr ? link::InterfaceInfo{}
                            : impl_->endpoint->interface_info();
}

link::BpfStatistics NetworkStack::bpf_statistics(
    std::error_code& error) const noexcept {
    if (impl_ == nullptr) {
        error = std::make_error_code(std::errc::bad_file_descriptor);
        return {};
    }
    return impl_->endpoint->bpf_statistics(error);
}

NetworkStackStatistics NetworkStack::statistics() const noexcept {
    return impl_ == nullptr ? NetworkStackStatistics{} : impl_->statistics;
}

}  // namespace vectornet::net

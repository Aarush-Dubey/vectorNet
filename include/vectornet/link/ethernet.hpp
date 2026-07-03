#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>

#include "vectornet/link/link_endpoint.hpp"

namespace vectornet::link {

using MacAddress = std::array<std::uint8_t, 6>;

inline constexpr std::size_t kEthernetHeaderBytes = 14;
inline constexpr std::size_t kEthernetMinimumFrameBytes = 60;
inline constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
inline constexpr std::uint16_t kEtherTypeArp = 0x0806;
inline constexpr std::uint16_t kEtherTypeVlan8021Q = 0x8100;
inline constexpr std::uint16_t kEtherTypeVlan8021Ad = 0x88A8;

struct EthernetHeader {
    MacAddress destination{};
    MacAddress source{};
    std::uint16_t ether_type{0};
};

struct EthernetFrameView {
    EthernetHeader header{};
    std::span<const std::byte> payload{};
};

enum class EthernetStatus : std::uint8_t {
    ok,
    frame_too_short,
    unsupported_vlan,
    output_too_small,
    payload_too_large,
};

[[nodiscard]] EthernetStatus parse_ethernet_frame(
    std::span<const std::byte> frame,
    EthernetFrameView& result) noexcept;

[[nodiscard]] EthernetStatus build_ethernet_frame(
    const MacAddress& destination,
    const MacAddress& source,
    std::uint16_t ether_type,
    std::span<const std::byte> payload,
    std::span<std::byte> output,
    std::size_t& frame_bytes) noexcept;

struct EthernetDropCounters {
    std::uint64_t short_frames{0};
    std::uint64_t vlan_frames{0};
};

using EthernetFrameCallback = void (*)(
    void* context,
    const EthernetHeader& header,
    std::span<const std::byte> payload,
    const CaptureMetadata& metadata) noexcept;

class EthernetEndpoint final {
public:
    EthernetEndpoint(const EthernetEndpoint&) = delete;
    EthernetEndpoint& operator=(const EthernetEndpoint&) = delete;
    EthernetEndpoint(EthernetEndpoint&&) noexcept;
    EthernetEndpoint& operator=(EthernetEndpoint&&) noexcept;
    ~EthernetEndpoint();

    [[nodiscard]] static std::unique_ptr<EthernetEndpoint> open(
        const LinkConfig& config,
        std::error_code& error);

    [[nodiscard]] std::error_code poll_frames(
        EthernetFrameCallback callback,
        void* context) noexcept;

    [[nodiscard]] std::error_code poll_frames_for(
        EthernetFrameCallback callback,
        void* context,
        std::uint32_t timeout_ms) noexcept;

    [[nodiscard]] std::error_code send_frame(
        const MacAddress& destination,
        std::uint16_t ether_type,
        std::span<const std::byte> payload,
        TxMetadata* metadata = nullptr) noexcept;

    [[nodiscard]] InterfaceInfo interface_info() const noexcept;
    [[nodiscard]] EthernetDropCounters drop_counters() const noexcept;
    [[nodiscard]] BpfStatistics bpf_statistics(std::error_code& error) const noexcept;

private:
    EthernetEndpoint(
        std::unique_ptr<LinkEndpoint> link,
        std::unique_ptr<std::byte[]> tx_buffer,
        std::size_t tx_capacity) noexcept;

    std::unique_ptr<LinkEndpoint> link_;
    std::unique_ptr<std::byte[]> tx_buffer_;
    std::size_t tx_capacity_{0};
    EthernetDropCounters drop_counters_{};
};

}  // namespace vectornet::link

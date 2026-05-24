#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <system_error>

namespace vectornet::link {

enum class CaptureFilter : std::uint8_t {
    none,
    stack_arp_ipv4_253,
};

struct LinkConfig {
    std::string interface_name;
    std::size_t requested_buffer_bytes{0};
    bool promiscuous{false};
    CaptureFilter capture_filter{CaptureFilter::none};
};

struct InterfaceInfo {
    std::array<std::uint8_t, 6> mac{};
    std::uint32_t mtu{0};
    std::size_t bpf_buffer_bytes{0};
};

struct CaptureMetadata {
    std::uint64_t capture_timestamp_ns{0};
    std::uint32_t captured_length{0};
    std::uint32_t wire_length{0};
};

struct BpfStatistics {
    std::uint32_t received{0};
    std::uint32_t dropped{0};
};

using FrameCallback = void (*)(
    void* context,
    std::span<const std::byte> frame,
    const CaptureMetadata& metadata) noexcept;

class LinkEndpoint final {
public:
    LinkEndpoint(const LinkEndpoint&) = delete;
    LinkEndpoint& operator=(const LinkEndpoint&) = delete;
    LinkEndpoint(LinkEndpoint&&) noexcept;
    LinkEndpoint& operator=(LinkEndpoint&&) noexcept;
    ~LinkEndpoint();

    [[nodiscard]] static std::unique_ptr<LinkEndpoint> open(
        const LinkConfig& config,
        std::error_code& error);

    [[nodiscard]] std::error_code poll_frames(
        FrameCallback callback,
        void* context) noexcept;

    [[nodiscard]] std::error_code send_frame(std::span<const std::byte> frame) noexcept;

    [[nodiscard]] InterfaceInfo interface_info() const noexcept;

    [[nodiscard]] BpfStatistics bpf_statistics(std::error_code& error) const noexcept;

private:
    struct Impl;

    explicit LinkEndpoint(std::unique_ptr<Impl> impl) noexcept;

    std::unique_ptr<Impl> impl_;
};

}  // namespace vectornet::link

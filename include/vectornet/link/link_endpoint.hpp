#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <system_error>

namespace vectornet::link {

struct LinkConfig {
    std::string interface_name;
    std::size_t requested_buffer_bytes{0};
    bool promiscuous{false};
};

struct InterfaceInfo {
    std::array<std::uint8_t, 6> mac{};
    std::uint32_t mtu{0};
};

using FrameCallback = void (*)(void* context, std::span<const std::byte> frame) noexcept;

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

private:
    struct Impl;

    explicit LinkEndpoint(std::unique_ptr<Impl> impl) noexcept;

    std::unique_ptr<Impl> impl_;
};

}  // namespace vectornet::link

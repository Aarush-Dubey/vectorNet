#pragma once

#if !defined(__APPLE__)
#error "Darwin BPF backend may only be compiled on macOS"
#endif

#include <cstddef>
#include <memory>
#include <span>
#include <system_error>

#include "vectornet/link/link_endpoint.hpp"

namespace vectornet::link::darwin {

class BpfBackend final {
public:
    BpfBackend(const BpfBackend&) = delete;
    BpfBackend& operator=(const BpfBackend&) = delete;
    ~BpfBackend();

    [[nodiscard]] static std::unique_ptr<BpfBackend> open(
        const LinkConfig& config,
        std::error_code& error);

    [[nodiscard]] std::error_code poll_frames(
        FrameCallback callback,
        void* context) noexcept;

    [[nodiscard]] std::error_code send_frame(std::span<const std::byte> frame) noexcept;

    [[nodiscard]] InterfaceInfo interface_info() const noexcept;

private:
    BpfBackend(int fd, InterfaceInfo info) noexcept;

    int fd_{-1};
    InterfaceInfo info_{};
};

}  // namespace vectornet::link::darwin

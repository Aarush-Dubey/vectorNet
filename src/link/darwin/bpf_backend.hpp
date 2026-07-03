#pragma once

#if !defined(__APPLE__)
#error "Darwin BPF backend may only be compiled on macOS"
#endif

#include <cstddef>
#include <ctime>
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

    [[nodiscard]] std::error_code poll_frames_for(
        FrameCallback callback,
        void* context,
        std::uint32_t timeout_ms) noexcept;

    [[nodiscard]] std::error_code send_frame(
        std::span<const std::byte> frame,
        TxMetadata* metadata) noexcept;

    [[nodiscard]] InterfaceInfo interface_info() const noexcept;

    [[nodiscard]] BpfStatistics bpf_statistics(std::error_code& error) const noexcept;

private:
    [[nodiscard]] std::error_code poll_frames_impl(
        FrameCallback callback,
        void* context,
        const timespec* timeout) noexcept;
    BpfBackend(
        int fd,
        int kqueue_fd,
        std::unique_ptr<std::byte[]> read_buffer,
        std::size_t read_buffer_size,
        InterfaceInfo info) noexcept;

    int fd_{-1};
    int kqueue_fd_{-1};
    std::unique_ptr<std::byte[]> read_buffer_;
    std::size_t read_buffer_size_{0};
    InterfaceInfo info_{};
};

}  // namespace vectornet::link::darwin

#include "bpf_backend.hpp"

#include <cerrno>

namespace vectornet::link::darwin {
namespace {

[[nodiscard]] std::error_code not_supported() noexcept {
    return std::make_error_code(std::errc::operation_not_supported);
}

}  // namespace

std::unique_ptr<BpfBackend> BpfBackend::open(
    const LinkConfig& config,
    std::error_code& error) noexcept {
    static_cast<void>(config);
    error = not_supported();
    return nullptr;
}

std::error_code BpfBackend::poll_frames(
    FrameCallback callback,
    void* context) noexcept {
    static_cast<void>(callback);
    static_cast<void>(context);
    return not_supported();
}

std::error_code BpfBackend::send_frame(std::span<const std::byte> frame) noexcept {
    static_cast<void>(frame);
    return not_supported();
}

InterfaceInfo BpfBackend::interface_info() const noexcept {
    return {};
}

}  // namespace vectornet::link::darwin

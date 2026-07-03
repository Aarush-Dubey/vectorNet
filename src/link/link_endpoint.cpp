#include "vectornet/link/link_endpoint.hpp"

#if defined(__APPLE__)
#include "darwin/bpf_backend.hpp"
#else
#error "vectorNet has no maintained backend for this platform"
#endif

#include <utility>

namespace vectornet::link {

struct LinkEndpoint::Impl {
    explicit Impl(std::unique_ptr<darwin::BpfBackend> native_backend) noexcept
        : backend(std::move(native_backend)) {}

    std::unique_ptr<darwin::BpfBackend> backend;
};

LinkEndpoint::LinkEndpoint(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

LinkEndpoint::LinkEndpoint(LinkEndpoint&&) noexcept = default;
LinkEndpoint& LinkEndpoint::operator=(LinkEndpoint&&) noexcept = default;
LinkEndpoint::~LinkEndpoint() = default;

std::unique_ptr<LinkEndpoint> LinkEndpoint::open(
    const LinkConfig& config,
    std::error_code& error) {
    auto backend = darwin::BpfBackend::open(config, error);
    if (!backend) {
        return nullptr;
    }

    auto impl = std::make_unique<Impl>(std::move(backend));
    error.clear();
    return std::unique_ptr<LinkEndpoint>(new LinkEndpoint(std::move(impl)));
}

std::error_code LinkEndpoint::poll_frames(
    FrameCallback callback,
    void* context) noexcept {
    if (!impl_ || !impl_->backend) {
        return std::make_error_code(std::errc::bad_file_descriptor);
    }
    return impl_->backend->poll_frames(callback, context);
}

std::error_code LinkEndpoint::poll_frames_for(
    FrameCallback callback,
    void* context,
    std::uint32_t timeout_ms) noexcept {
    if (!impl_ || !impl_->backend) {
        return std::make_error_code(std::errc::bad_file_descriptor);
    }
    return impl_->backend->poll_frames_for(callback, context, timeout_ms);
}

std::error_code LinkEndpoint::send_frame(
    std::span<const std::byte> frame,
    TxMetadata* metadata) noexcept {
    if (!impl_ || !impl_->backend) {
        return std::make_error_code(std::errc::bad_file_descriptor);
    }
    return impl_->backend->send_frame(frame, metadata);
}

InterfaceInfo LinkEndpoint::interface_info() const noexcept {
    if (!impl_ || !impl_->backend) {
        return {};
    }
    return impl_->backend->interface_info();
}

BpfStatistics LinkEndpoint::bpf_statistics(std::error_code& error) const noexcept {
    if (!impl_ || !impl_->backend) {
        error = std::make_error_code(std::errc::bad_file_descriptor);
        return {};
    }
    return impl_->backend->bpf_statistics(error);
}

}  // namespace vectornet::link

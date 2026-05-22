#include "vectornet/link/link_endpoint.hpp"

#include <limits>
#include <system_error>
#include <type_traits>

namespace {

void discard_frame(
    void*,
    std::span<const std::byte>,
    const vectornet::link::CaptureMetadata&) noexcept {}

}  // namespace

int main() {
    static_assert(std::is_nothrow_invocable_v<vectornet::link::FrameCallback,
                                               void*,
                                               std::span<const std::byte>,
                                               const vectornet::link::CaptureMetadata&>);

    vectornet::link::LinkConfig config{
        .interface_name = "",
        .requested_buffer_bytes = 0,
        .promiscuous = false,
    };

    std::error_code error;
    auto endpoint = vectornet::link::LinkEndpoint::open(config, error);
    if (endpoint) {
        return 1;
    }
    if (error != std::errc::invalid_argument) {
        return 2;
    }

    config.interface_name = "ignored";
    config.requested_buffer_bytes =
        static_cast<std::size_t>(std::numeric_limits<unsigned int>::max()) + 1U;
    endpoint = vectornet::link::LinkEndpoint::open(config, error);
    if (endpoint || error != std::errc::value_too_large) {
        return 3;
    }

    vectornet::link::FrameCallback callback = &discard_frame;
    if (callback == nullptr) {
        return 4;
    }

    return 0;
}

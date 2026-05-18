#include "vectornet/link/link_endpoint.hpp"

#include <system_error>
#include <type_traits>

namespace {

void discard_frame(void*, std::span<const std::byte>) noexcept {}

}  // namespace

int main() {
    static_assert(std::is_nothrow_invocable_v<vectornet::link::FrameCallback,
                                               void*,
                                               std::span<const std::byte>>);

    vectornet::link::LinkConfig config{
        .interface_name = "en0",
        .requested_buffer_bytes = 0,
        .promiscuous = false,
    };

    std::error_code error;
    auto endpoint = vectornet::link::LinkEndpoint::open(config, error);
    if (endpoint) {
        return 1;
    }
    if (error != std::errc::operation_not_supported) {
        return 2;
    }

    vectornet::link::FrameCallback callback = &discard_frame;
    if (callback == nullptr) {
        return 3;
    }

    return 0;
}

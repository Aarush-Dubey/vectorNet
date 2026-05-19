#include "bpf_backend.hpp"

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <limits>
#include <string_view>

namespace vectornet::link::darwin {
namespace {

constexpr std::size_t kMaxBpfDevices = 256;

class ScopedFd final {
public:
    explicit ScopedFd(int fd = -1) noexcept : fd_(fd) {}
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    ~ScopedFd() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    [[nodiscard]] int get() const noexcept { return fd_; }

    [[nodiscard]] int release() noexcept {
        const int fd = fd_;
        fd_ = -1;
        return fd;
    }

private:
    int fd_;
};

[[nodiscard]] std::error_code errno_error() noexcept {
    return {errno, std::generic_category()};
}

[[nodiscard]] bool copy_interface_name(
    std::string_view name,
    ifreq& request,
    std::error_code& error) noexcept {
    if (name.empty() || name.size() >= IFNAMSIZ) {
        error = std::make_error_code(std::errc::invalid_argument);
        return false;
    }

    std::memset(&request, 0, sizeof(request));
    std::memcpy(request.ifr_name, name.data(), name.size());
    request.ifr_name[name.size()] = '\0';
    return true;
}

[[nodiscard]] ScopedFd open_available_bpf(std::error_code& error) noexcept {
    bool saw_busy_device = false;
    for (std::size_t index = 0; index < kMaxBpfDevices; ++index) {
        char path[32]{};
        const int length = std::snprintf(path, sizeof(path), "/dev/bpf%zu", index);
        if (length <= 0 || static_cast<std::size_t>(length) >= sizeof(path)) {
            error = std::make_error_code(std::errc::filename_too_long);
            return ScopedFd();
        }

        const int fd = ::open(path, O_RDWR | O_CLOEXEC);
        if (fd >= 0) {
            error.clear();
            return ScopedFd(fd);
        }
        if (errno == EBUSY) {
            saw_busy_device = true;
            continue;
        }
        if (errno == ENOENT) {
            continue;
        }

        error = errno_error();
        return ScopedFd();
    }

    error = saw_busy_device
        ? std::make_error_code(std::errc::device_or_resource_busy)
        : std::make_error_code(std::errc::no_such_device);
    return ScopedFd();
}

[[nodiscard]] bool query_interface_info(
    std::string_view interface_name,
    InterfaceInfo& info,
    std::error_code& error) noexcept {
    ifreq request{};
    if (!copy_interface_name(interface_name, request, error)) {
        return false;
    }

    ScopedFd control_socket(::socket(AF_INET, SOCK_DGRAM, 0));
    if (control_socket.get() < 0) {
        error = errno_error();
        return false;
    }
    if (::ioctl(control_socket.get(), SIOCGIFMTU, &request) < 0) {
        error = errno_error();
        return false;
    }
    if (request.ifr_mtu <= 0) {
        error = std::make_error_code(std::errc::protocol_error);
        return false;
    }
    info.mtu = static_cast<std::uint32_t>(request.ifr_mtu);

    ifaddrs* addresses = nullptr;
    if (::getifaddrs(&addresses) != 0) {
        error = errno_error();
        return false;
    }

    bool found_mac = false;
    for (const ifaddrs* current = addresses; current != nullptr; current = current->ifa_next) {
        if (current->ifa_addr == nullptr || current->ifa_name == nullptr) {
            continue;
        }
        if (interface_name != current->ifa_name || current->ifa_addr->sa_family != AF_LINK) {
            continue;
        }

        const auto* link_address = reinterpret_cast<const sockaddr_dl*>(current->ifa_addr);
        if (static_cast<std::size_t>(link_address->sdl_alen) != info.mac.size()) {
            continue;
        }
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(LLADDR(link_address));
        std::copy_n(bytes, info.mac.size(), info.mac.begin());
        found_mac = true;
        break;
    }
    ::freeifaddrs(addresses);

    if (!found_mac) {
        error = std::make_error_code(std::errc::address_not_available);
        return false;
    }

    error.clear();
    return true;
}

}  // namespace

BpfBackend::BpfBackend(int fd, InterfaceInfo info) noexcept
    : fd_(fd), info_(info) {}

BpfBackend::~BpfBackend() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

std::unique_ptr<BpfBackend> BpfBackend::open(
    const LinkConfig& config,
    std::error_code& error) {
    if (config.interface_name.empty() || config.interface_name.size() >= IFNAMSIZ) {
        error = std::make_error_code(std::errc::invalid_argument);
        return nullptr;
    }
    if (config.requested_buffer_bytes > std::numeric_limits<unsigned int>::max()) {
        error = std::make_error_code(std::errc::value_too_large);
        return nullptr;
    }

    ScopedFd fd = open_available_bpf(error);
    if (fd.get() < 0) {
        return nullptr;
    }

    bpf_version version{};
    if (::ioctl(fd.get(), BIOCVERSION, &version) < 0) {
        error = errno_error();
        return nullptr;
    }
    if (version.bv_major != BPF_MAJOR_VERSION || version.bv_minor < BPF_MINOR_VERSION) {
        error = std::make_error_code(std::errc::protocol_error);
        return nullptr;
    }

    unsigned int buffer_bytes = config.requested_buffer_bytes == 0
        ? static_cast<unsigned int>(BPF_MAXBUFSIZE)
        : static_cast<unsigned int>(config.requested_buffer_bytes);
    if (::ioctl(fd.get(), BIOCSBLEN, &buffer_bytes) < 0) {
        error = errno_error();
        return nullptr;
    }

    ifreq request{};
    if (!copy_interface_name(config.interface_name, request, error)) {
        return nullptr;
    }
    if (::ioctl(fd.get(), BIOCSETIF, &request) < 0) {
        error = errno_error();
        return nullptr;
    }

    unsigned int data_link_type = 0;
    if (::ioctl(fd.get(), BIOCGDLT, &data_link_type) < 0) {
        error = errno_error();
        return nullptr;
    }
    if (data_link_type != DLT_EN10MB) {
        error = std::make_error_code(std::errc::protocol_not_supported);
        return nullptr;
    }

    unsigned int enabled = 1;
    if (::ioctl(fd.get(), BIOCSHDRCMPLT, &enabled) < 0) {
        error = errno_error();
        return nullptr;
    }
    if (config.promiscuous && ::ioctl(fd.get(), BIOCPROMISC) < 0) {
        error = errno_error();
        return nullptr;
    }

    unsigned int see_sent = 0;
    if (::ioctl(fd.get(), BIOCSSEESENT, &see_sent) < 0) {
        error = errno_error();
        return nullptr;
    }

    InterfaceInfo info{};
    info.bpf_buffer_bytes = buffer_bytes;
    if (!query_interface_info(config.interface_name, info, error)) {
        return nullptr;
    }

    auto backend = std::unique_ptr<BpfBackend>(new BpfBackend(fd.get(), info));
    static_cast<void>(fd.release());
    error.clear();
    return backend;
}

std::error_code BpfBackend::poll_frames(
    FrameCallback callback,
    void* context) noexcept {
    static_cast<void>(callback);
    static_cast<void>(context);
    return std::make_error_code(std::errc::operation_not_supported);
}

std::error_code BpfBackend::send_frame(std::span<const std::byte> frame) noexcept {
    if (frame.empty()) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    if (frame.size() > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max())) {
        return std::make_error_code(std::errc::value_too_large);
    }

    const ssize_t written = ::write(fd_, frame.data(), frame.size());
    if (written < 0) {
        return errno_error();
    }
    if (static_cast<std::size_t>(written) != frame.size()) {
        return std::make_error_code(std::errc::io_error);
    }
    return {};
}

InterfaceInfo BpfBackend::interface_info() const noexcept {
    return info_;
}

}  // namespace vectornet::link::darwin

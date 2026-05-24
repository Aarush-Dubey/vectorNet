#include "bpf_backend.hpp"
#include "vectornet/link/ethernet.hpp"

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <limits>
#include <memory>
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

[[nodiscard]] bool install_capture_filter(
    int fd,
    CaptureFilter selection,
    const MacAddress& local_mac,
    std::error_code& error) noexcept {
    if (selection == CaptureFilter::none) {
        return true;
    }
    if (selection != CaptureFilter::stack_arp_ipv4_253) {
        error = std::make_error_code(std::errc::invalid_argument);
        return false;
    }

    const std::uint32_t local_prefix =
        static_cast<std::uint32_t>(local_mac[0]) << 24U |
        static_cast<std::uint32_t>(local_mac[1]) << 16U |
        static_cast<std::uint32_t>(local_mac[2]) << 8U |
        static_cast<std::uint32_t>(local_mac[3]);
    const std::uint32_t local_suffix =
        static_cast<std::uint32_t>(local_mac[4]) << 8U |
        static_cast<std::uint32_t>(local_mac[5]);

    std::array<bpf_insn, 14> instructions{{
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, local_prefix, 0, 2),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, local_suffix, 3, 9),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xFFFFFFFFU, 0, 8),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xFFFFU, 0, 6),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kEtherTypeArp, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kEtherTypeIpv4, 0, 3),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 253, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, std::numeric_limits<std::uint32_t>::max()),
        BPF_STMT(BPF_RET | BPF_K, 0),
    }};
    bpf_program program{
        .bf_len = static_cast<unsigned int>(instructions.size()),
        .bf_insns = instructions.data(),
    };
    if (::ioctl(fd, BIOCSETF, &program) < 0) {
        error = errno_error();
        return false;
    }
    error.clear();
    return true;
}

}  // namespace

BpfBackend::BpfBackend(
    int fd,
    int kqueue_fd,
    std::unique_ptr<std::byte[]> read_buffer,
    std::size_t read_buffer_size,
    InterfaceInfo info) noexcept
    : fd_(fd),
      kqueue_fd_(kqueue_fd),
      read_buffer_(std::move(read_buffer)),
      read_buffer_size_(read_buffer_size),
      info_(info) {}

BpfBackend::~BpfBackend() {
    if (kqueue_fd_ >= 0) {
        ::close(kqueue_fd_);
    }
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
    auto read_buffer = std::make_unique<std::byte[]>(buffer_bytes);

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
    if (!query_interface_info(config.interface_name, info, error) ||
        !install_capture_filter(fd.get(), config.capture_filter, info.mac, error)) {
        return nullptr;
    }

    unsigned int immediate = 1;
    if (::ioctl(fd.get(), BIOCIMMEDIATE, &immediate) < 0) {
        error = errno_error();
        return nullptr;
    }
    if (::ioctl(fd.get(), BIOCFLUSH) < 0) {
        error = errno_error();
        return nullptr;
    }

    ScopedFd event_queue(::kqueue());
    if (event_queue.get() < 0) {
        error = errno_error();
        return nullptr;
    }
    struct kevent change{};
    EV_SET(
        &change,
        static_cast<std::uintptr_t>(fd.get()),
        EVFILT_READ,
        EV_ADD | EV_ENABLE,
        0,
        0,
        nullptr);
    if (::kevent(event_queue.get(), &change, 1, nullptr, 0, nullptr) < 0) {
        error = errno_error();
        return nullptr;
    }

    auto backend = std::unique_ptr<BpfBackend>(new BpfBackend(
        fd.get(),
        event_queue.get(),
        std::move(read_buffer),
        buffer_bytes,
        info));
    static_cast<void>(fd.release());
    static_cast<void>(event_queue.release());
    error.clear();
    return backend;
}

std::error_code BpfBackend::poll_frames(
    FrameCallback callback,
    void* context) noexcept {
    if (callback == nullptr) {
        return std::make_error_code(std::errc::invalid_argument);
    }

    struct kevent event{};
    int ready = 0;
    do {
        ready = ::kevent(kqueue_fd_, nullptr, 0, &event, 1, nullptr);
    } while (ready < 0 && errno == EINTR);
    if (ready < 0) {
        return errno_error();
    }
    if ((event.flags & EV_ERROR) != 0) {
        return {static_cast<int>(event.data), std::generic_category()};
    }

    ssize_t bytes_read = 0;
    do {
        bytes_read = ::read(fd_, read_buffer_.get(), read_buffer_size_);
    } while (bytes_read < 0 && errno == EINTR);
    if (bytes_read < 0) {
        return errno_error();
    }
    if (bytes_read == 0) {
        return std::make_error_code(std::errc::io_error);
    }

    const std::size_t batch_bytes = static_cast<std::size_t>(bytes_read);
    std::size_t offset = 0;
    constexpr std::size_t kBpfHeaderFieldsBytes =
        offsetof(bpf_hdr, bh_hdrlen) + sizeof(bpf_hdr::bh_hdrlen);
    while (offset < batch_bytes) {
        if (batch_bytes - offset < kBpfHeaderFieldsBytes) {
            return std::make_error_code(std::errc::protocol_error);
        }

        bpf_hdr header{};
        std::memcpy(&header, read_buffer_.get() + offset, kBpfHeaderFieldsBytes);
        const std::size_t header_bytes = header.bh_hdrlen;
        const std::size_t captured_bytes = header.bh_caplen;
        if (header_bytes < kBpfHeaderFieldsBytes || header_bytes > batch_bytes - offset) {
            return std::make_error_code(std::errc::protocol_error);
        }
        const std::size_t frame_offset = offset + header_bytes;
        if (captured_bytes > batch_bytes - frame_offset) {
            return std::make_error_code(std::errc::protocol_error);
        }
        if (header.bh_tstamp.tv_sec < 0 || header.bh_tstamp.tv_usec < 0 ||
            header.bh_tstamp.tv_usec >= 1'000'000) {
            return std::make_error_code(std::errc::protocol_error);
        }

        constexpr std::uint64_t kNanosecondsPerSecond = 1'000'000'000ULL;
        constexpr std::uint64_t kNanosecondsPerMicrosecond = 1'000ULL;
        const auto seconds = static_cast<std::uint64_t>(header.bh_tstamp.tv_sec);
        if (seconds > std::numeric_limits<std::uint64_t>::max() /
                          kNanosecondsPerSecond) {
            return std::make_error_code(std::errc::value_too_large);
        }
        const CaptureMetadata metadata{
            .capture_timestamp_ns =
                seconds * kNanosecondsPerSecond +
                static_cast<std::uint64_t>(header.bh_tstamp.tv_usec) *
                    kNanosecondsPerMicrosecond,
            .captured_length = header.bh_caplen,
            .wire_length = header.bh_datalen,
        };
        callback(
            context,
            std::span<const std::byte>(read_buffer_.get() + frame_offset, captured_bytes),
            metadata);

        const std::size_t record_bytes = header_bytes + captured_bytes;
        const std::size_t remaining_bytes = batch_bytes - offset;
        if (record_bytes == remaining_bytes) {
            offset = batch_bytes;
            continue;
        }
        const std::size_t aligned_bytes = BPF_WORDALIGN(record_bytes);
        if (aligned_bytes < record_bytes || aligned_bytes > remaining_bytes) {
            return std::make_error_code(std::errc::protocol_error);
        }
        offset += aligned_bytes;
    }
    return {};
}

std::error_code BpfBackend::send_frame(std::span<const std::byte> frame) noexcept {
    if (frame.size() < kEthernetHeaderBytes) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    const std::size_t maximum_frame_bytes =
        static_cast<std::size_t>(info_.mtu) + kEthernetHeaderBytes;
    if (frame.size() > maximum_frame_bytes) {
        return std::make_error_code(std::errc::message_size);
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

BpfStatistics BpfBackend::bpf_statistics(std::error_code& error) const noexcept {
    bpf_stat statistics{};
    if (::ioctl(fd_, BIOCGSTATS, &statistics) < 0) {
        error = errno_error();
        return {};
    }
    error.clear();
    return {
        .received = statistics.bs_recv,
        .dropped = statistics.bs_drop,
    };
}

}  // namespace vectornet::link::darwin

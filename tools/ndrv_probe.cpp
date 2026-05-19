#include <net/if.h>
#include <net/if_dl.h>
#include <net/ndrv.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <string>
#include <string_view>

namespace {

constexpr std::uint16_t kProbeEtherType = 0x88B5;
constexpr std::size_t kEthernetHeaderBytes = 14;
constexpr std::size_t kMinimumFrameBytes = 60;

[[nodiscard]] bool parse_mac(
    std::string_view text,
    std::array<std::uint8_t, 6>& mac) noexcept {
    unsigned int values[6]{};
    int consumed = 0;
    const std::string owned(text);
    const int matched = std::sscanf(
        owned.c_str(),
        "%2x:%2x:%2x:%2x:%2x:%2x%n",
        &values[0],
        &values[1],
        &values[2],
        &values[3],
        &values[4],
        &values[5],
        &consumed);
    if (matched != 6 || consumed != static_cast<int>(text.size())) {
        return false;
    }
    for (std::size_t index = 0; index < mac.size(); ++index) {
        if (values[index] > 0xFFU) {
            return false;
        }
        mac[index] = static_cast<std::uint8_t>(values[index]);
    }
    return true;
}

[[nodiscard]] bool interface_mac(
    std::string_view name,
    std::array<std::uint8_t, 6>& mac) noexcept {
    ifaddrs* addresses = nullptr;
    if (::getifaddrs(&addresses) != 0) {
        return false;
    }

    bool found = false;
    for (const ifaddrs* current = addresses; current != nullptr; current = current->ifa_next) {
        if (current->ifa_addr == nullptr || current->ifa_name == nullptr) {
            continue;
        }
        if (name != current->ifa_name || current->ifa_addr->sa_family != AF_LINK) {
            continue;
        }
        const auto* link = reinterpret_cast<const sockaddr_dl*>(current->ifa_addr);
        if (static_cast<std::size_t>(link->sdl_alen) != mac.size()) {
            continue;
        }
        std::memcpy(mac.data(), LLADDR(link), mac.size());
        found = true;
        break;
    }
    ::freeifaddrs(addresses);
    return found;
}

[[nodiscard]] int fail(const char* operation) noexcept {
    const int error = errno;
    std::fprintf(
        stderr,
        "{\"status\":\"error\",\"operation\":\"%s\",\"errno\":%d}\n",
        operation,
        error);
    return 1;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 4 || std::string_view(argv[1]) != "--interface") {
        std::fprintf(stderr, "usage: %s --interface IFACE DESTINATION_MAC\n", argv[0]);
        return 64;
    }

    const std::string_view interface_name(argv[2]);
    if (interface_name.empty() || interface_name.size() >= IFNAMSIZ) {
        std::fprintf(stderr, "invalid interface\n");
        return 64;
    }

    std::array<std::uint8_t, 6> destination{};
    std::array<std::uint8_t, 6> source{};
    if (!parse_mac(argv[3], destination) || !interface_mac(interface_name, source)) {
        std::fprintf(stderr, "invalid link metadata\n");
        return 64;
    }

    const int fd = ::socket(AF_NDRV, SOCK_RAW, 0);
    if (fd < 0) {
        return fail("socket");
    }

    sockaddr_ndrv address{};
    address.snd_len = static_cast<unsigned char>(sizeof(address));
    address.snd_family = static_cast<unsigned char>(AF_NDRV);
    std::memcpy(address.snd_name, interface_name.data(), interface_name.size());
    address.snd_name[interface_name.size()] = '\0';
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
        const int result = fail("bind");
        ::close(fd);
        return result;
    }
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
        const int result = fail("connect");
        ::close(fd);
        return result;
    }

    std::array<std::byte, kMinimumFrameBytes> frame{};
    for (std::size_t index = 0; index < destination.size(); ++index) {
        frame[index] = static_cast<std::byte>(destination[index]);
        frame[index + destination.size()] = static_cast<std::byte>(source[index]);
    }
    frame[12] = static_cast<std::byte>((kProbeEtherType >> 8U) & 0xFFU);
    frame[13] = static_cast<std::byte>(kProbeEtherType & 0xFFU);
    constexpr std::array<std::byte, 8> magic{
        static_cast<std::byte>('V'), static_cast<std::byte>('N'),
        static_cast<std::byte>('E'), static_cast<std::byte>('T'),
        static_cast<std::byte>('N'), static_cast<std::byte>('D'),
        static_cast<std::byte>('R'), static_cast<std::byte>('V'),
    };
    std::memcpy(frame.data() + kEthernetHeaderBytes, magic.data(), magic.size());

    const ssize_t written = ::send(fd, frame.data(), frame.size(), 0);
    if (written < 0) {
        const int result = fail("send");
        ::close(fd);
        return result;
    }
    ::close(fd);
    if (static_cast<std::size_t>(written) != frame.size()) {
        std::fprintf(stderr, "{\"status\":\"error\",\"operation\":\"short_send\"}\n");
        return 1;
    }

    std::printf("{\"status\":\"sent\",\"api\":\"AF_NDRV\",\"bytes\":%zu}\n", frame.size());
    return 0;
}

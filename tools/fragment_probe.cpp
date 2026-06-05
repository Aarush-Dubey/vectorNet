#include "vectornet/net/ipv4.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <string_view>

namespace {

void write_le16(std::byte* output, std::uint16_t value) noexcept {
    output[0] = static_cast<std::byte>(value & 0xFFU);
    output[1] = static_cast<std::byte>((value >> 8U) & 0xFFU);
}

void write_le32(std::byte* output, std::uint32_t value) noexcept {
    output[0] = static_cast<std::byte>(value & 0xFFU);
    output[1] = static_cast<std::byte>((value >> 8U) & 0xFFU);
    output[2] = static_cast<std::byte>((value >> 16U) & 0xFFU);
    output[3] = static_cast<std::byte>((value >> 24U) & 0xFFU);
}

struct CaptureContext {
    std::ofstream* output{nullptr};
    std::uint32_t seconds{0};
    std::uint32_t microseconds{0};
    std::array<std::size_t, 8> sizes{};
    std::array<std::uint16_t, 8> offsets{};
    std::size_t count{0};
    bool failed{false};
};

bool write_fragment(void* opaque, std::span<const std::byte> packet) noexcept {
    auto& context = *static_cast<CaptureContext*>(opaque);
    if (context.count >= context.sizes.size() ||
        packet.size() > std::numeric_limits<std::uint32_t>::max()) {
        context.failed = true;
        return false;
    }
    vectornet::net::Ipv4PacketView parsed{};
    if (vectornet::net::parse_ipv4_packet(packet, parsed) !=
        vectornet::net::Ipv4Status::ok) {
        context.failed = true;
        return false;
    }

    std::array<std::byte, 16> record{};
    write_le32(record.data(), context.seconds);
    write_le32(
        record.data() + 4,
        static_cast<std::uint32_t>(context.microseconds + context.count));
    write_le32(record.data() + 8, static_cast<std::uint32_t>(packet.size()));
    write_le32(record.data() + 12, static_cast<std::uint32_t>(packet.size()));
    context.output->write(
        reinterpret_cast<const char*>(record.data()),
        static_cast<std::streamsize>(record.size()));
    context.output->write(
        reinterpret_cast<const char*>(packet.data()),
        static_cast<std::streamsize>(packet.size()));
    if (!*context.output) {
        context.failed = true;
        return false;
    }
    context.sizes[context.count] = packet.size();
    context.offsets[context.count] = static_cast<std::uint16_t>(
        parsed.header.flags_fragment_offset &
        vectornet::net::kIpv4FragmentOffsetMask);
    ++context.count;
    return true;
}

[[nodiscard]] bool write_global_header(std::ofstream& output) {
    std::array<std::byte, 24> header{};
    write_le32(header.data(), 0xA1B2C3D4U);
    write_le16(header.data() + 4, 2);
    write_le16(header.data() + 6, 4);
    write_le32(header.data() + 16, 65'535);
    write_le32(header.data() + 20, 12);  // DLT_RAW
    output.write(
        reinterpret_cast<const char*>(header.data()),
        static_cast<std::streamsize>(header.size()));
    return static_cast<bool>(output);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " OUTPUT.pcap\n";
        return 64;
    }
    const std::string_view path(argv[1]);
    std::ofstream output(std::string(path), std::ios::binary | std::ios::trunc);
    if (!output || !write_global_header(output)) {
        std::cerr << "cannot create pcap\n";
        return 1;
    }

    timespec now{};
    if (::clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0 ||
        now.tv_nsec < 0) {
        std::cerr << "clock_gettime failed\n";
        return 1;
    }
    CaptureContext context{
        .output = &output,
        .seconds = static_cast<std::uint32_t>(now.tv_sec),
        .microseconds = static_cast<std::uint32_t>(now.tv_nsec / 1'000),
    };
    std::array<std::byte, 4'000> payload{};
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>(index & 0xFFU);
    }
    std::array<std::byte, 1'500> scratch{};
    const vectornet::net::Ipv4Header header{
        .identification = 0x1234,
        .ttl = vectornet::net::kVectorNetTtl,
        .protocol = vectornet::net::kVectorNetProtocol,
        .source = 0xC6130001U,
        .destination = 0xC6130002U,
    };
    const auto status = vectornet::net::fragment_ipv4_payload(
        header, payload, 1'500, scratch, &write_fragment, &context);
    output.close();
    if (status != vectornet::net::Ipv4Status::ok || context.failed ||
        context.count != 3) {
        std::cerr << "fragment capture failed\n";
        return 1;
    }
    std::cout << "{\"fragments\":" << context.count
              << ",\"packet_bytes\":[" << context.sizes[0] << ','
              << context.sizes[1] << ',' << context.sizes[2]
              << "],\"offset_units\":[" << context.offsets[0] << ','
              << context.offsets[1] << ',' << context.offsets[2]
              << "],\"identification\":4660,\"mtu\":1500,\"payload_bytes\":4000}"
              << '\n';
    return 0;
}

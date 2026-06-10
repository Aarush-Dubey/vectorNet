#include "vectornet/net/reassembly.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

namespace {

struct Result {
    std::array<std::byte, 64> expected{};
    std::array<bool, 64> received{};
    std::size_t calls{0};
};

bool verify(
    void* opaque,
    const vectornet::net::ReassemblyKey&,
    std::span<const std::byte> payload) noexcept {
    auto& result = *static_cast<Result*>(opaque);
    if (payload.size() != result.expected.size() ||
        !std::equal(payload.begin(), payload.end(), result.expected.begin())) {
        std::abort();
    }
    ++result.calls;
    return true;
}

struct Fragment {
    std::uint16_t offset_flags{0};
    std::size_t begin{0};
    std::size_t bytes{0};
    std::uint8_t variant{0};
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(
    const std::uint8_t* data,
    std::size_t size) {
    if (size == 0) {
        return 0;
    }
    std::array<std::byte, 64> source{};
    for (std::size_t index = 0; index < source.size(); ++index) {
        source[index] = static_cast<std::byte>(
            data[index % size] ^ static_cast<std::uint8_t>(index));
    }
    Result result{};

    std::array<Fragment, 3> fragments{{
        {.offset_flags = vectornet::net::kIpv4FlagMoreFragments,
         .begin = 0,
         .bytes = 24,
         .variant = 0x00},
        {.offset_flags = static_cast<std::uint16_t>(
             vectornet::net::kIpv4FlagMoreFragments | 2U),
         .begin = 16,
         .bytes = 32,
         .variant = 0x40},
        {.offset_flags = 5, .begin = 40, .bytes = 24, .variant = 0x80},
    }};
    for (std::size_t index = fragments.size(); index > 1; --index) {
        const std::size_t choice = data[(index - 1) % size] % index;
        std::swap(fragments[index - 1], fragments[choice]);
    }

    vectornet::net::ReassemblyTable table(1, 1'000);
    for (std::size_t index = 0; index < fragments.size(); ++index) {
        const auto& fragment = fragments[index];
        std::array<std::byte, 32> fragment_bytes{};
        for (std::size_t byte = 0; byte < fragment.bytes; ++byte) {
            const std::size_t position = fragment.begin + byte;
            fragment_bytes[byte] = source[position] ^
                static_cast<std::byte>(fragment.variant);
            if (!result.received[position]) {
                result.expected[position] = fragment_bytes[byte];
                result.received[position] = true;
            }
        }
        vectornet::net::Ipv4Header header{
            .identification = 0xF00D,
            .flags_fragment_offset = fragment.offset_flags,
            .ttl = vectornet::net::kVectorNetTtl,
            .protocol = vectornet::net::kVectorNetProtocol,
            .source = 0xC6130001U,
            .destination = 0xC6130002U,
        };
        const auto payload = std::span<const std::byte>(fragment_bytes)
                                 .first(fragment.bytes);
        const auto status = table.insert(header, payload, index, &verify, &result);
        if (status != vectornet::net::ReassemblyStatus::pending &&
            status != vectornet::net::ReassemblyStatus::complete) {
            std::abort();
        }
        if ((data[index % size] & 1U) != 0U &&
            status != vectornet::net::ReassemblyStatus::complete) {
            const auto duplicate = table.insert(
                header, payload, index, &verify, &result);
            if (duplicate != vectornet::net::ReassemblyStatus::pending) {
                std::abort();
            }
        }
    }
    if (result.calls != 1) {
        std::abort();
    }
    return 0;
}

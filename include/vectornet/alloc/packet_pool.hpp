#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace vectornet::alloc {

inline constexpr std::size_t kPacketBufferBytes = 2'048;
inline constexpr std::size_t kDefaultPacketBufferCount = 4'096;

struct alignas(64) PacketBuffer {
    std::array<std::byte, kPacketBufferBytes> data{};
    std::uint16_t length{0};
};

static_assert(alignof(PacketBuffer) == 64);
static_assert(sizeof(PacketBuffer) % 64 == 0);

struct PacketPoolStatistics {
    std::uint64_t acquired{0};
    std::uint64_t released{0};
    std::uint64_t exhausted{0};
    std::uint64_t invalid_release{0};
};

class PacketPool final {
public:
    explicit PacketPool(std::size_t capacity = kDefaultPacketBufferCount);
    PacketPool(const PacketPool&) = delete;
    PacketPool& operator=(const PacketPool&) = delete;
    PacketPool(PacketPool&&) noexcept;
    PacketPool& operator=(PacketPool&&) noexcept;
    ~PacketPool();

    [[nodiscard]] PacketBuffer* acquire() noexcept;
    [[nodiscard]] bool release(PacketBuffer* buffer) noexcept;

    [[nodiscard]] std::size_t capacity() const noexcept;
    [[nodiscard]] std::size_t available() const noexcept;
    [[nodiscard]] PacketPoolStatistics statistics() const noexcept;

private:
    [[nodiscard]] bool index_of(
        const PacketBuffer* buffer,
        std::size_t& index) const noexcept;

    std::unique_ptr<PacketBuffer[]> storage_;
    std::unique_ptr<std::size_t[]> freelist_;
    std::unique_ptr<std::uint8_t[]> in_use_;
    std::size_t capacity_{0};
    std::size_t available_{0};
    PacketPoolStatistics statistics_{};
};

}  // namespace vectornet::alloc

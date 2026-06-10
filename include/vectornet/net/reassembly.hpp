#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "vectornet/net/ipv4.hpp"

namespace vectornet::net {

inline constexpr std::size_t kIpv4MaximumPayloadBytes = 65'535 - kIpv4HeaderBytes;
inline constexpr std::size_t kDefaultReassemblySlots = 64;
inline constexpr std::size_t kMaximumReassemblyHoles = 8'192;
inline constexpr std::uint64_t kDefaultReassemblyTimeoutNs = 5'000'000'000ULL;

struct ReassemblyKey {
    Ipv4Address source{0};
    Ipv4Address destination{0};
    std::uint16_t identification{0};
    std::uint8_t protocol{0};

    [[nodiscard]] friend bool operator==(
        const ReassemblyKey& left,
        const ReassemblyKey& right) noexcept = default;
};

enum class ReassemblyStatus : std::uint8_t {
    pending,
    complete,
    malformed,
    table_full,
    hole_capacity_exhausted,
    callback_rejected,
};

using ReassemblyCallback = bool (*)(
    void* context,
    const ReassemblyKey& key,
    std::span<const std::byte> payload) noexcept;

struct ReassemblyStatistics {
    std::uint64_t completed{0};
    std::uint64_t malformed{0};
    std::uint64_t table_full{0};
    std::uint64_t timed_out{0};
    std::uint64_t duplicate_fragments{0};
    std::uint64_t overlap_bytes_ignored{0};
};

class ReassemblyTable final {
public:
    explicit ReassemblyTable(
        std::size_t capacity = kDefaultReassemblySlots,
        std::uint64_t timeout_ns = kDefaultReassemblyTimeoutNs);
    ReassemblyTable(const ReassemblyTable&) = delete;
    ReassemblyTable& operator=(const ReassemblyTable&) = delete;
    ReassemblyTable(ReassemblyTable&&) noexcept;
    ReassemblyTable& operator=(ReassemblyTable&&) noexcept;
    ~ReassemblyTable();

    [[nodiscard]] ReassemblyStatus insert(
        const Ipv4Header& header,
        std::span<const std::byte> fragment_payload,
        std::uint64_t now_ns,
        ReassemblyCallback callback,
        void* callback_context) noexcept;

    [[nodiscard]] std::size_t sweep(std::uint64_t now_ns) noexcept;
    [[nodiscard]] std::size_t active_slots() const noexcept;
    [[nodiscard]] std::size_t capacity() const noexcept;
    [[nodiscard]] ReassemblyStatistics statistics() const noexcept;

private:
    struct Hole {
        std::uint32_t begin{0};
        std::uint32_t end{0};
    };

    struct Slot {
        ReassemblyKey key{};
        std::array<std::byte, kIpv4MaximumPayloadBytes> data{};
        std::array<Hole, kMaximumReassemblyHoles> holes{};
        std::size_t hole_count{0};
        std::size_t highest_received_end{0};
        std::size_t total_length{0};
        std::uint64_t created_at_ns{0};
        bool total_length_known{false};
        bool active{false};
    };

    [[nodiscard]] Slot* find_or_create(
        const ReassemblyKey& key,
        std::uint64_t now_ns) noexcept;
    [[nodiscard]] bool establish_total_length(
        Slot& slot,
        std::size_t total_length) noexcept;
    [[nodiscard]] bool subtract_received_range(
        Slot& slot,
        std::size_t begin,
        std::size_t end) noexcept;
    [[nodiscard]] std::size_t copy_unreceived_bytes(
        Slot& slot,
        std::size_t begin,
        std::span<const std::byte> fragment_payload) noexcept;
    [[nodiscard]] bool is_complete(const Slot& slot) const noexcept;
    void release(Slot& slot) noexcept;

    std::unique_ptr<Slot[]> slots_;
    std::size_t capacity_{0};
    std::uint64_t timeout_ns_{0};
    ReassemblyStatistics statistics_{};
};

}  // namespace vectornet::net

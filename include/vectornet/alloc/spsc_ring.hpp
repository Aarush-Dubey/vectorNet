#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <type_traits>

namespace vectornet::alloc {

template <typename T, std::size_t Capacity>
class SpscRing final {
    static_assert(Capacity >= 2);
    static_assert((Capacity & (Capacity - 1)) == 0,
                  "SPSC capacity must be a power of two");
    static_assert(std::is_trivially_copyable_v<T>,
                  "SPSC values must have trivial ownership");

public:
    SpscRing() = default;
    SpscRing(const SpscRing&) = delete;
    SpscRing& operator=(const SpscRing&) = delete;

    [[nodiscard]] bool try_push(const T& value) noexcept {
        const std::size_t write = producer_.value.load(std::memory_order_relaxed);
        const std::size_t read = consumer_.value.load(std::memory_order_acquire);
        if (write - read == Capacity) {
            return false;
        }
        slots_[write & (Capacity - 1)] = value;
        producer_.value.store(write + 1, std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool try_pop(T& value) noexcept {
        const std::size_t read = consumer_.value.load(std::memory_order_relaxed);
        const std::size_t write = producer_.value.load(std::memory_order_acquire);
        if (read == write) {
            return false;
        }
        value = slots_[read & (Capacity - 1)];
        consumer_.value.store(read + 1, std::memory_order_release);
        return true;
    }

    [[nodiscard]] std::size_t approximate_size() const noexcept {
        const std::size_t write = producer_.value.load(std::memory_order_acquire);
        const std::size_t read = consumer_.value.load(std::memory_order_acquire);
        return write - read;
    }

    [[nodiscard]] static constexpr std::size_t capacity() noexcept {
        return Capacity;
    }

private:
    struct alignas(64) Cursor {
        std::atomic<std::size_t> value{0};
    };
    static_assert(sizeof(Cursor) == 64);

    Cursor producer_{};
    Cursor consumer_{};
    alignas(64) std::array<T, Capacity> slots_{};
};

}  // namespace vectornet::alloc

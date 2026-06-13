#include "vectornet/alloc/packet_pool.hpp"
#include "vectornet/alloc/spsc_ring.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>

namespace {

constexpr std::size_t kQueueCapacity = 1'024;
constexpr std::uint64_t kTransfers = 1'000'000;
using Buffer = vectornet::alloc::PacketBuffer;
using Ring = vectornet::alloc::SpscRing<Buffer*, kQueueCapacity>;

}  // namespace

int main() {
    vectornet::alloc::PacketPool producer_pool(kQueueCapacity);
    Ring outbound;
    Ring recycle;
    std::atomic<bool> failed{false};
    std::atomic<std::uint64_t> consumed{0};

    std::thread consumer([&] {
        std::uint64_t expected = 0;
        while (expected < kTransfers && !failed.load(std::memory_order_relaxed)) {
            Buffer* buffer = nullptr;
            if (!outbound.try_pop(buffer)) {
                std::this_thread::yield();
                continue;
            }
            std::uint64_t observed = 0;
            std::memcpy(&observed, buffer->data.data(), sizeof(observed));
            if (buffer->length != sizeof(observed) || observed != expected) {
                failed.store(true, std::memory_order_relaxed);
                break;
            }
            while (!recycle.try_push(buffer)) {
                if (failed.load(std::memory_order_relaxed)) {
                    return;
                }
                std::this_thread::yield();
            }
            ++expected;
        }
        consumed.store(expected, std::memory_order_release);
    });

    std::uint64_t produced = 0;
    std::uint64_t reclaimed = 0;
    while (produced < kTransfers && !failed.load(std::memory_order_relaxed)) {
        Buffer* returned = nullptr;
        while (recycle.try_pop(returned)) {
            if (!producer_pool.release(returned)) {
                failed.store(true, std::memory_order_relaxed);
                break;
            }
            ++reclaimed;
        }
        if (failed.load(std::memory_order_relaxed)) {
            break;
        }
        Buffer* buffer = producer_pool.acquire();
        if (buffer == nullptr) {
            std::this_thread::yield();
            continue;
        }
        std::memcpy(buffer->data.data(), &produced, sizeof(produced));
        buffer->length = sizeof(produced);
        while (!outbound.try_push(buffer)) {
            if (failed.load(std::memory_order_relaxed)) {
                break;
            }
            std::this_thread::yield();
        }
        if (failed.load(std::memory_order_relaxed)) {
            break;
        }
        ++produced;
    }

    while (reclaimed < produced && !failed.load(std::memory_order_relaxed)) {
        Buffer* pending = nullptr;
        if (!recycle.try_pop(pending)) {
            std::this_thread::yield();
            continue;
        }
        if (!producer_pool.release(pending)) {
            failed.store(true, std::memory_order_relaxed);
            break;
        }
        ++reclaimed;
    }
    consumer.join();
    Buffer* returned = nullptr;
    while (recycle.try_pop(returned)) {
        if (!producer_pool.release(returned)) {
            failed.store(true, std::memory_order_relaxed);
            break;
        }
        ++reclaimed;
    }

    const bool passed = !failed.load(std::memory_order_relaxed) &&
        produced == kTransfers &&
        consumed.load(std::memory_order_acquire) == kTransfers &&
        reclaimed == kTransfers &&
        producer_pool.available() == producer_pool.capacity();
    std::printf(
        "{\"phase\":12,\"gate\":\"tsan-spsc-owner-handoff\","
        "\"transfers\":%llu,\"produced\":%llu,\"consumed\":%llu,"
        "\"reclaimed\":%llu,\"queue_capacity\":%zu,"
        "\"pool_available\":%zu,\"status\":\"%s\"}\n",
        static_cast<unsigned long long>(kTransfers),
        static_cast<unsigned long long>(produced),
        static_cast<unsigned long long>(consumed.load(std::memory_order_relaxed)),
        static_cast<unsigned long long>(reclaimed),
        kQueueCapacity,
        producer_pool.available(),
        passed ? "pass" : "fail");
    return passed ? 0 : 1;
}

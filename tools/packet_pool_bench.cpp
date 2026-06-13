#include "vectornet/alloc/packet_pool.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>

namespace {

using GateBegin = void (*)() noexcept;
using GateEnd = void (*)(std::uint64_t*, std::size_t) noexcept;

constexpr std::size_t kBatchSize = 128;
constexpr std::size_t kIterations = 20'000;
constexpr std::size_t kCounterCount = 8;
volatile std::uintptr_t calibration_sink = 0;

__attribute__((noinline)) bool exercise_interposed_symbols() {
    void* malloc_block = std::malloc(17);
    void* calloc_block = std::calloc(2, 19);
    if (malloc_block == nullptr || calloc_block == nullptr) {
        return false;
    }
    malloc_block = std::realloc(malloc_block, 37);
    if (malloc_block == nullptr) {
        std::free(calloc_block);
        return false;
    }
    calibration_sink = reinterpret_cast<std::uintptr_t>(malloc_block) ^
        reinterpret_cast<std::uintptr_t>(calloc_block);
    std::free(malloc_block);
    std::free(calloc_block);

    auto* scalar = new std::byte{0x2A};
    auto* array = new std::byte[23];
    calibration_sink = calibration_sink ^
        reinterpret_cast<std::uintptr_t>(scalar) ^
        reinterpret_cast<std::uintptr_t>(array);
    delete scalar;
    delete[] array;
    return true;
}

}  // namespace

int main() {
    const auto gate_begin = reinterpret_cast<GateBegin>(
        dlsym(RTLD_DEFAULT, "vectornet_allocation_gate_begin"));
    const auto gate_end = reinterpret_cast<GateEnd>(
        dlsym(RTLD_DEFAULT, "vectornet_allocation_gate_end"));
    if (gate_begin == nullptr || gate_end == nullptr) {
        std::fputs("phase11: allocation interposer not loaded\n", stderr);
        return 2;
    }

    vectornet::alloc::PacketPool pool;
    std::array<vectornet::alloc::PacketBuffer*, kBatchSize> batch{};
    std::uint64_t checksum = 0;
    std::array<std::uint64_t, kCounterCount> calibration{};
    gate_begin();
    if (!exercise_interposed_symbols()) {
        return 5;
    }
    gate_end(calibration.data(), calibration.size());
    for (const auto count : calibration) {
        if (count == 0) {
            std::fputs("phase11: interposer calibration missed a symbol\n", stderr);
            return 6;
        }
    }

    gate_begin();
    for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
        for (std::size_t index = 0; index < batch.size(); ++index) {
            batch[index] = pool.acquire();
            if (batch[index] == nullptr) {
                return 3;
            }
            batch[index]->length = 1'200;
            batch[index]->data[0] = static_cast<std::byte>(iteration ^ index);
            checksum += static_cast<std::uint8_t>(batch[index]->data[0]);
        }
        for (auto* buffer : batch) {
            if (!pool.release(buffer)) {
                return 4;
            }
        }
    }
    std::array<std::uint64_t, kCounterCount> counts{};
    gate_end(counts.data(), counts.size());

    std::uint64_t total = 0;
    for (const auto count : counts) {
        total += count;
    }
    const auto statistics = pool.statistics();
    std::printf(
        "{\"phase\":11,\"gate\":\"packet-pool-hot-window-allocation\","
        "\"iterations\":%zu,\"batch\":%zu,\"operations\":%zu,"
        "\"malloc\":%llu,\"calloc\":%llu,\"realloc\":%llu,"
        "\"free\":%llu,\"new\":%llu,\"new_array\":%llu,"
        "\"delete\":%llu,\"delete_array\":%llu,\"total\":%llu,"
        "\"calibration_min\":%llu,"
        "\"pool_acquired\":%llu,\"pool_released\":%llu,"
        "\"pool_exhausted\":%llu,\"checksum\":%llu,\"status\":\"%s\"}\n",
        kIterations,
        kBatchSize,
        kIterations * kBatchSize * 2,
        static_cast<unsigned long long>(counts[0]),
        static_cast<unsigned long long>(counts[1]),
        static_cast<unsigned long long>(counts[2]),
        static_cast<unsigned long long>(counts[3]),
        static_cast<unsigned long long>(counts[4]),
        static_cast<unsigned long long>(counts[5]),
        static_cast<unsigned long long>(counts[6]),
        static_cast<unsigned long long>(counts[7]),
        static_cast<unsigned long long>(total),
        static_cast<unsigned long long>(*std::min_element(
            calibration.begin(), calibration.end())),
        static_cast<unsigned long long>(statistics.acquired),
        static_cast<unsigned long long>(statistics.released),
        static_cast<unsigned long long>(statistics.exhausted),
        static_cast<unsigned long long>(checksum),
        total == 0 ? "pass" : "fail");
    return total == 0 && pool.available() == pool.capacity() ? 0 : 1;
}

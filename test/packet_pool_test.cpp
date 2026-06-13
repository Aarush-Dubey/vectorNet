#include "vectornet/alloc/packet_pool.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

namespace {

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

}  // namespace

int main() {
    vectornet::alloc::PacketPool pool(4);
    std::array<vectornet::alloc::PacketBuffer*, 4> held{};
    for (auto& buffer : held) {
        buffer = pool.acquire();
        if (!expect(buffer != nullptr, "pool exhausted too early") ||
            !expect(reinterpret_cast<std::uintptr_t>(buffer) % 64 == 0,
                    "packet buffer is not cache-line aligned")) {
            return 1;
        }
        buffer->length = 42;
    }
    if (!expect(pool.available() == 0, "available count mismatch at exhaustion") ||
        !expect(pool.acquire() == nullptr, "exhausted pool returned a buffer") ||
        !expect(pool.release(held[1]), "valid release failed") ||
        !expect(held[1]->length == 0, "release did not clear length") ||
        !expect(!pool.release(held[1]), "double release accepted")) {
        return 1;
    }
    vectornet::alloc::PacketBuffer foreign{};
    if (!expect(!pool.release(&foreign), "foreign buffer accepted") ||
        !expect(pool.acquire() == held[1], "freelist did not return released buffer")) {
        return 1;
    }
    for (std::size_t index = 0; index < held.size(); ++index) {
        if (index != 1 && !expect(pool.release(held[index]), "final release failed")) {
            return 1;
        }
    }
    if (!expect(pool.release(held[1]), "reacquired buffer release failed") ||
        !expect(pool.available() == pool.capacity(), "pool did not recover capacity")) {
        return 1;
    }
    const auto statistics = pool.statistics();
    return expect(statistics.acquired == 5, "acquire statistic mismatch") &&
                   expect(statistics.released == 5, "release statistic mismatch") &&
                   expect(statistics.exhausted == 1, "exhaustion statistic mismatch") &&
                   expect(statistics.invalid_release == 2,
                          "invalid-release statistic mismatch")
               ? 0
               : 1;
}

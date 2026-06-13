#include "vectornet/alloc/spsc_ring.hpp"

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
    vectornet::alloc::SpscRing<std::uint32_t, 4> ring;
    std::uint32_t value = 0;
    if (!expect(!ring.try_pop(value), "empty ring produced a value") ||
        !expect(ring.try_push(10), "first push failed") ||
        !expect(ring.try_push(20), "second push failed") ||
        !expect(ring.try_push(30), "third push failed") ||
        !expect(ring.try_push(40), "fourth push failed") ||
        !expect(!ring.try_push(50), "full ring accepted a value") ||
        !expect(ring.approximate_size() == 4, "full ring size mismatch")) {
        return 1;
    }
    for (const std::uint32_t expected : {10U, 20U, 30U, 40U}) {
        if (!expect(ring.try_pop(value), "ring lost a value") ||
            !expect(value == expected, "ring reordered values")) {
            return 1;
        }
    }
    return expect(!ring.try_pop(value), "drained ring produced a value") &&
                   expect(ring.approximate_size() == 0, "drained ring size mismatch")
               ? 0
               : 1;
}

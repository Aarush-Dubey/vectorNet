#pragma once

#include <bit>
#include <cstdint>

namespace vectornet::transport {

[[nodiscard]] constexpr bool sequence_less(
    std::uint32_t left,
    std::uint32_t right) noexcept {
    return std::bit_cast<std::int32_t>(left - right) < 0;
}

[[nodiscard]] constexpr bool sequence_less_equal(
    std::uint32_t left,
    std::uint32_t right) noexcept {
    return left == right || sequence_less(left, right);
}

[[nodiscard]] constexpr bool sequence_greater(
    std::uint32_t left,
    std::uint32_t right) noexcept {
    return sequence_less(right, left);
}

}  // namespace vectornet::transport

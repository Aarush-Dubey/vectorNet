#include "vectornet/transport/receive_ranges.hpp"

#include <array>
#include <cstdint>
#include <initializer_list>
#include <iostream>

namespace {

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

[[nodiscard]] bool expect_sacks(
    const vectornet::transport::ReceiveRangeSet& ranges,
    std::initializer_list<vectornet::transport::SackBlock> expected) {
    std::array<vectornet::transport::SackBlock, 4> output{};
    const std::size_t count = ranges.generate_sacks(output);
    if (!expect(count == expected.size(), "SACK count mismatch")) {
        return false;
    }
    std::size_t index = 0;
    for (const auto& block : expected) {
        if (!expect(output[index++] == block, "SACK block mismatch")) {
            return false;
        }
    }
    return true;
}

}  // namespace

int main() {
    using namespace vectornet::transport;
    ReceiveRangeSet ranges(1'000);
    if (!expect(ranges.insert(1'300, 1'400).status == ReceiveRangeStatus::accepted,
                "first out-of-order range rejected") ||
        !expect_sacks(ranges, {{1'300, 1'400}}) ||
        !expect(ranges.insert(1'100, 1'200).status == ReceiveRangeStatus::accepted,
                "nearer range rejected") ||
        !expect_sacks(ranges, {{1'100, 1'200}, {1'300, 1'400}}) ||
        !expect(ranges.insert(1'200, 1'300).status == ReceiveRangeStatus::accepted,
                "bridge range rejected") ||
        !expect_sacks(ranges, {{1'100, 1'400}})) {
        return 1;
    }
    const auto filled = ranges.insert(1'000, 1'100);
    if (!expect(filled.cumulative_ack == 1'400,
                "cumulative ACK did not cross buffered ranges") ||
        !expect(filled.newly_contiguous_bytes == 400,
                "newly contiguous byte count mismatch") ||
        !expect_sacks(ranges, {}) ||
        !expect(ranges.insert(1'100, 1'200).status == ReceiveRangeStatus::duplicate,
                "old duplicate not recognized")) {
        return 1;
    }

    ReceiveRangeSet wrapping(0xFFFFFFF0U);
    if (!expect(wrapping.insert(0x00000010U, 0x00000020U).status ==
                    ReceiveRangeStatus::accepted,
                "wrapped out-of-order range rejected") ||
        !expect(wrapping.insert(0xFFFFFFF0U, 0x00000010U).cumulative_ack ==
                    0x00000020U,
                "wrapped cumulative ACK failed")) {
        return 1;
    }

    ReceiveRangeSet bounded(0, 2);
    return expect(bounded.insert(10, 20).status == ReceiveRangeStatus::accepted,
                  "bounded first insert failed") &&
                   expect(bounded.insert(30, 40).status == ReceiveRangeStatus::accepted,
                          "bounded second insert failed") &&
                   expect(bounded.insert(50, 60).status == ReceiveRangeStatus::full,
                          "full receive set accepted another gap")
               ? 0
               : 1;
}

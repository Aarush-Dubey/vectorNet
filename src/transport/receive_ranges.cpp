#include "vectornet/transport/receive_ranges.hpp"

#include <algorithm>
#include "vectornet/transport/sequence.hpp"

namespace vectornet::transport {

ReceiveRangeSet::ReceiveRangeSet(
    std::uint32_t initial_sequence,
    std::size_t capacity) noexcept
    : capacity_(std::min(capacity, kReceiveRangeCapacity)),
      cumulative_ack_(initial_sequence) {}

ReceiveRangeResult ReceiveRangeSet::insert(
    std::uint32_t start,
    std::uint32_t end) noexcept {
    if (start == end) {
        return {ReceiveRangeStatus::invalid_range, cumulative_ack_, 0};
    }
    const std::uint32_t length = end - start;
    if (length >= 0x80000000U) {
        return {ReceiveRangeStatus::outside_window, cumulative_ack_, 0};
    }
    if (sequence_less_equal(end, cumulative_ack_)) {
        return {ReceiveRangeStatus::duplicate, cumulative_ack_, 0};
    }
    if (sequence_less(start, cumulative_ack_)) {
        start = cumulative_ack_;
    }
    if (start - cumulative_ack_ >= 0x80000000U) {
        return {ReceiveRangeStatus::outside_window, cumulative_ack_, 0};
    }

    const std::uint32_t previous_ack = cumulative_ack_;
    if (start == cumulative_ack_) {
        cumulative_ack_ = end;
        advance_contiguous();
        return {
            ReceiveRangeStatus::accepted,
            cumulative_ack_,
            cumulative_ack_ - previous_ack,
        };
    }

    std::size_t first = 0;
    while (first < size_ && sequence_less(ranges_[first].end, start)) {
        ++first;
    }
    std::uint32_t merged_start = start;
    std::uint32_t merged_end = end;
    std::size_t last = first;
    while (last < size_ &&
           sequence_less_equal(ranges_[last].start, merged_end)) {
        if (sequence_less(ranges_[last].start, merged_start)) {
            merged_start = ranges_[last].start;
        }
        if (sequence_less(merged_end, ranges_[last].end)) {
            merged_end = ranges_[last].end;
        }
        ++last;
    }

    if (first == last && size_ == capacity_) {
        return {ReceiveRangeStatus::full, cumulative_ack_, 0};
    }
    if (first < last) {
        ranges_[first] = {merged_start, merged_end};
        const std::size_t removed = last - first - 1;
        for (std::size_t index = last; index < size_; ++index) {
            ranges_[index - removed] = ranges_[index];
        }
        size_ -= removed;
    } else {
        for (std::size_t index = size_; index > first; --index) {
            ranges_[index] = ranges_[index - 1];
        }
        ranges_[first] = {merged_start, merged_end};
        ++size_;
    }
    return {ReceiveRangeStatus::accepted, cumulative_ack_, 0};
}

std::size_t ReceiveRangeSet::generate_sacks(
    std::span<SackBlock> output) const noexcept {
    const std::size_t count = std::min({
        size_, output.size(), kMaximumSackBlocks});
    for (std::size_t index = 0; index < count; ++index) {
        output[index] = ranges_[index];
    }
    return count;
}

std::uint32_t ReceiveRangeSet::cumulative_ack() const noexcept {
    return cumulative_ack_;
}

const SackBlock* ReceiveRangeSet::at(std::size_t index) const noexcept {
    return index < size_ ? &ranges_[index] : nullptr;
}

std::size_t ReceiveRangeSet::size() const noexcept {
    return size_;
}

std::size_t ReceiveRangeSet::capacity() const noexcept {
    return capacity_;
}

void ReceiveRangeSet::remove(std::size_t index) noexcept {
    for (std::size_t move = index + 1; move < size_; ++move) {
        ranges_[move - 1] = ranges_[move];
    }
    --size_;
}

void ReceiveRangeSet::advance_contiguous() noexcept {
    while (size_ != 0 &&
           sequence_less_equal(ranges_[0].start, cumulative_ack_)) {
        if (sequence_less(cumulative_ack_, ranges_[0].end)) {
            cumulative_ack_ = ranges_[0].end;
        }
        remove(0);
    }
}

}  // namespace vectornet::transport

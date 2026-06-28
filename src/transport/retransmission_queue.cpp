#include "vectornet/transport/retransmission_queue.hpp"

#include <algorithm>

#include "vectornet/transport/sequence.hpp"

namespace vectornet::transport {

RetransmissionQueue::RetransmissionQueue(std::size_t capacity) noexcept
    : capacity_(std::min(capacity, kRetransmissionCapacity)) {}

EnqueueStatus RetransmissionQueue::enqueue(
    const PendingSegment& segment) noexcept {
    if (segment.buffer == nullptr ||
        segment.sequence_start == segment.sequence_end) {
        return EnqueueStatus::invalid_segment;
    }
    if (size_ == capacity_) {
        return EnqueueStatus::full;
    }
    if (size_ != 0 &&
        !sequence_less(segments_[size_ - 1].sequence_start,
                       segment.sequence_start)) {
        return EnqueueStatus::out_of_order;
    }
    segments_[size_++] = segment;
    return EnqueueStatus::accepted;
}

AcknowledgeResult RetransmissionQueue::acknowledge(
    std::uint32_t cumulative_ack,
    alloc::PacketPool& owner_pool) noexcept {
    AcknowledgeResult result{};
    while (result.released < size_ &&
           sequence_less_equal(
               segments_[result.released].sequence_end,
               cumulative_ack)) {
        if (!owner_pool.release(segments_[result.released].buffer)) {
            result.pool_error = true;
            for (std::size_t index = result.released; index < size_; ++index) {
                segments_[index - result.released] = segments_[index];
            }
            size_ -= result.released;
            return result;
        }
        ++result.released;
    }
    if (result.released == 0) {
        return result;
    }
    for (std::size_t index = result.released; index < size_; ++index) {
        segments_[index - result.released] = segments_[index];
    }
    size_ -= result.released;
    return result;
}

AcknowledgeResult RetransmissionQueue::clear(
    alloc::PacketPool& owner_pool) noexcept {
    AcknowledgeResult result{};
    for (std::size_t index = 0; index < size_; ++index) {
        if (!owner_pool.release(segments_[index].buffer)) {
            result.pool_error = true;
            for (std::size_t retained = index; retained < size_; ++retained) {
                segments_[retained - result.released] = segments_[retained];
            }
            size_ -= result.released;
            return result;
        }
        ++result.released;
    }
    size_ = 0;
    return result;
}

SackProcessingResult RetransmissionQueue::apply_sacks(
    std::span<const SackBlock> sacks) noexcept {
    SackProcessingResult result{};
    for (const auto& block : sacks) {
        if (block.start == block.end) {
            ++result.invalid_blocks;
            continue;
        }
        for (std::size_t index = 0; index < size_; ++index) {
            auto& segment = segments_[index];
            const bool fully_covered =
                sequence_less_equal(block.start, segment.sequence_start) &&
                sequence_less_equal(segment.sequence_end, block.end);
            if (fully_covered && !segment.sacked) {
                segment.sacked = true;
                ++result.newly_sacked;
            }
        }
    }
    return result;
}

std::size_t RetransmissionQueue::collect_unsacked(
    std::span<PendingSegment*> output) noexcept {
    std::size_t written = 0;
    for (std::size_t index = 0; index < size_ && written < output.size(); ++index) {
        if (!segments_[index].sacked) {
            output[written++] = &segments_[index];
        }
    }
    return written;
}

PendingSegment* RetransmissionQueue::lowest_unsacked() noexcept {
    for (std::size_t index = 0; index < size_; ++index) {
        if (!segments_[index].sacked) {
            return &segments_[index];
        }
    }
    return nullptr;
}

const PendingSegment* RetransmissionQueue::at(std::size_t index) const noexcept {
    return index < size_ ? &segments_[index] : nullptr;
}

PendingSegment* RetransmissionQueue::at(std::size_t index) noexcept {
    return index < size_ ? &segments_[index] : nullptr;
}

std::size_t RetransmissionQueue::size() const noexcept {
    return size_;
}

std::size_t RetransmissionQueue::capacity() const noexcept {
    return capacity_;
}

bool RetransmissionQueue::empty() const noexcept {
    return size_ == 0;
}

}  // namespace vectornet::transport

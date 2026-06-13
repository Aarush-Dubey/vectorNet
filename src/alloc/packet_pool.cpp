#include "vectornet/alloc/packet_pool.hpp"

#include <cstdint>
#include <limits>

namespace vectornet::alloc {

PacketPool::PacketPool(std::size_t capacity)
    : storage_(capacity == 0 ? nullptr : std::make_unique<PacketBuffer[]>(capacity)),
      freelist_(capacity == 0 ? nullptr : std::make_unique<std::size_t[]>(capacity)),
      in_use_(capacity == 0 ? nullptr : std::make_unique<std::uint8_t[]>(capacity)),
      capacity_(capacity),
      available_(capacity) {
    for (std::size_t index = 0; index < capacity_; ++index) {
        freelist_[index] = capacity_ - index - 1;
        in_use_[index] = 0;
    }
}

PacketPool::PacketPool(PacketPool&&) noexcept = default;
PacketPool& PacketPool::operator=(PacketPool&&) noexcept = default;
PacketPool::~PacketPool() = default;

PacketBuffer* PacketPool::acquire() noexcept {
    if (available_ == 0) {
        ++statistics_.exhausted;
        return nullptr;
    }
    const std::size_t index = freelist_[--available_];
    in_use_[index] = 1;
    storage_[index].length = 0;
    ++statistics_.acquired;
    return &storage_[index];
}

bool PacketPool::release(PacketBuffer* buffer) noexcept {
    std::size_t index = 0;
    if (!index_of(buffer, index) || in_use_[index] == 0) {
        ++statistics_.invalid_release;
        return false;
    }
    buffer->length = 0;
    in_use_[index] = 0;
    freelist_[available_++] = index;
    ++statistics_.released;
    return true;
}

std::size_t PacketPool::capacity() const noexcept {
    return capacity_;
}

std::size_t PacketPool::available() const noexcept {
    return available_;
}

PacketPoolStatistics PacketPool::statistics() const noexcept {
    return statistics_;
}

bool PacketPool::index_of(
    const PacketBuffer* buffer,
    std::size_t& index) const noexcept {
    if (buffer == nullptr || capacity_ == 0) {
        return false;
    }
    const auto begin = reinterpret_cast<std::uintptr_t>(storage_.get());
    const auto address = reinterpret_cast<std::uintptr_t>(buffer);
    if (capacity_ > std::numeric_limits<std::uintptr_t>::max() /
                        sizeof(PacketBuffer)) {
        return false;
    }
    const auto storage_bytes = capacity_ * sizeof(PacketBuffer);
    if (address < begin || address - begin >= storage_bytes) {
        return false;
    }
    const auto offset = address - begin;
    if (offset % sizeof(PacketBuffer) != 0) {
        return false;
    }
    index = offset / sizeof(PacketBuffer);
    return true;
}

}  // namespace vectornet::alloc

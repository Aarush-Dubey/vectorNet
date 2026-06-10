#include "vectornet/net/reassembly.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace vectornet::net {

ReassemblyTable::ReassemblyTable(
    std::size_t capacity,
    std::uint64_t timeout_ns)
    : slots_(capacity == 0 ? nullptr : std::make_unique<Slot[]>(capacity)),
      capacity_(capacity),
      timeout_ns_(timeout_ns) {}

ReassemblyTable::ReassemblyTable(ReassemblyTable&&) noexcept = default;
ReassemblyTable& ReassemblyTable::operator=(ReassemblyTable&&) noexcept = default;
ReassemblyTable::~ReassemblyTable() = default;

ReassemblyStatus ReassemblyTable::insert(
    const Ipv4Header& header,
    std::span<const std::byte> fragment_payload,
    std::uint64_t now_ns,
    ReassemblyCallback callback,
    void* callback_context) noexcept {
    if (callback == nullptr) {
        ++statistics_.malformed;
        return ReassemblyStatus::malformed;
    }
    const std::size_t offset_units =
        header.flags_fragment_offset & kIpv4FragmentOffsetMask;
    const std::size_t offset = offset_units * 8U;
    const bool more =
        (header.flags_fragment_offset & kIpv4FlagMoreFragments) != 0;
    if ((more && (fragment_payload.empty() || fragment_payload.size() % 8U != 0)) ||
        (offset != 0 && fragment_payload.empty()) ||
        offset > kIpv4MaximumPayloadBytes ||
        fragment_payload.size() > kIpv4MaximumPayloadBytes - offset) {
        ++statistics_.malformed;
        return ReassemblyStatus::malformed;
    }
    const std::size_t end = offset + fragment_payload.size();
    const ReassemblyKey key{
        .source = header.source,
        .destination = header.destination,
        .identification = header.identification,
        .protocol = header.protocol,
    };

    if (offset == 0 && !more) {
        const bool accepted = callback(callback_context, key, fragment_payload);
        if (accepted) {
            ++statistics_.completed;
            return ReassemblyStatus::complete;
        }
        return ReassemblyStatus::callback_rejected;
    }

    Slot* slot = find_or_create(key, now_ns);
    if (slot == nullptr) {
        ++statistics_.table_full;
        return ReassemblyStatus::table_full;
    }
    if ((slot->total_length_known && end > slot->total_length) ||
        (!more && !establish_total_length(*slot, end))) {
        ++statistics_.malformed;
        release(*slot);
        return ReassemblyStatus::malformed;
    }

    const std::size_t copied =
        copy_unreceived_bytes(*slot, offset, fragment_payload);
    if (!fragment_payload.empty() && copied == 0) {
        ++statistics_.duplicate_fragments;
    }
    statistics_.overlap_bytes_ignored += fragment_payload.size() - copied;
    slot->highest_received_end = std::max(slot->highest_received_end, end);
    if (!subtract_received_range(*slot, offset, end)) {
        release(*slot);
        return ReassemblyStatus::hole_capacity_exhausted;
    }
    if (!is_complete(*slot)) {
        return ReassemblyStatus::pending;
    }

    const bool accepted = callback(
        callback_context,
        slot->key,
        std::span<const std::byte>(slot->data.data(), slot->total_length));
    release(*slot);
    if (!accepted) {
        return ReassemblyStatus::callback_rejected;
    }
    ++statistics_.completed;
    return ReassemblyStatus::complete;
}

std::size_t ReassemblyTable::sweep(std::uint64_t now_ns) noexcept {
    std::size_t expired = 0;
    for (std::size_t index = 0; index < capacity_; ++index) {
        auto& slot = slots_[index];
        if (!slot.active) {
            continue;
        }
        const bool timed_out = now_ns >= slot.created_at_ns &&
            now_ns - slot.created_at_ns >= timeout_ns_;
        if (timed_out) {
            release(slot);
            ++expired;
            ++statistics_.timed_out;
        }
    }
    return expired;
}

std::size_t ReassemblyTable::active_slots() const noexcept {
    std::size_t active = 0;
    for (std::size_t index = 0; index < capacity_; ++index) {
        if (slots_[index].active) {
            ++active;
        }
    }
    return active;
}

std::size_t ReassemblyTable::capacity() const noexcept {
    return capacity_;
}

ReassemblyStatistics ReassemblyTable::statistics() const noexcept {
    return statistics_;
}

ReassemblyTable::Slot* ReassemblyTable::find_or_create(
    const ReassemblyKey& key,
    std::uint64_t now_ns) noexcept {
    Slot* available = nullptr;
    for (std::size_t index = 0; index < capacity_; ++index) {
        auto& slot = slots_[index];
        if (slot.active && slot.key == key) {
            return &slot;
        }
        if (!slot.active && available == nullptr) {
            available = &slot;
        }
    }
    if (available == nullptr) {
        return nullptr;
    }
    available->key = key;
    available->hole_count = 1;
    available->holes[0] = Hole{
        .begin = 0,
        .end = static_cast<std::uint32_t>(kIpv4MaximumPayloadBytes),
    };
    available->highest_received_end = 0;
    available->total_length = 0;
    available->created_at_ns = now_ns;
    available->total_length_known = false;
    available->active = true;
    return available;
}

bool ReassemblyTable::establish_total_length(
    Slot& slot,
    std::size_t total_length) noexcept {
    if ((slot.total_length_known && slot.total_length != total_length) ||
        slot.highest_received_end > total_length) {
        return false;
    }
    slot.total_length = total_length;
    slot.total_length_known = true;
    std::size_t write = 0;
    for (std::size_t read = 0; read < slot.hole_count; ++read) {
        Hole hole = slot.holes[read];
        if (hole.begin >= total_length) {
            continue;
        }
        hole.end = static_cast<std::uint32_t>(
            std::min<std::size_t>(hole.end, total_length));
        if (hole.begin < hole.end) {
            slot.holes[write++] = hole;
        }
    }
    slot.hole_count = write;
    return true;
}

bool ReassemblyTable::subtract_received_range(
    Slot& slot,
    std::size_t begin,
    std::size_t end) noexcept {
    if (begin == end) {
        return true;
    }
    std::size_t index = 0;
    while (index < slot.hole_count) {
        auto& hole = slot.holes[index];
        if (end <= hole.begin || begin >= hole.end) {
            ++index;
            continue;
        }
        if (begin <= hole.begin && end >= hole.end) {
            for (std::size_t move = index + 1; move < slot.hole_count; ++move) {
                slot.holes[move - 1] = slot.holes[move];
            }
            --slot.hole_count;
            continue;
        }
        if (begin <= hole.begin) {
            hole.begin = static_cast<std::uint32_t>(end);
            ++index;
            continue;
        }
        if (end >= hole.end) {
            hole.end = static_cast<std::uint32_t>(begin);
            ++index;
            continue;
        }
        if (slot.hole_count >= slot.holes.size()) {
            return false;
        }
        for (std::size_t move = slot.hole_count; move > index + 1; --move) {
            slot.holes[move] = slot.holes[move - 1];
        }
        const std::uint32_t original_end = hole.end;
        hole.end = static_cast<std::uint32_t>(begin);
        slot.holes[index + 1] = Hole{
            .begin = static_cast<std::uint32_t>(end),
            .end = original_end,
        };
        ++slot.hole_count;
        return true;
    }
    return true;
}

std::size_t ReassemblyTable::copy_unreceived_bytes(
    Slot& slot,
    std::size_t begin,
    std::span<const std::byte> fragment_payload) noexcept {
    const std::size_t end = begin + fragment_payload.size();
    std::size_t copied = 0;
    for (std::size_t index = 0; index < slot.hole_count; ++index) {
        const auto& hole = slot.holes[index];
        const std::size_t copy_begin =
            std::max(begin, static_cast<std::size_t>(hole.begin));
        const std::size_t copy_end =
            std::min(end, static_cast<std::size_t>(hole.end));
        if (copy_begin >= copy_end) {
            continue;
        }
        const std::size_t bytes = copy_end - copy_begin;
        std::memcpy(
            slot.data.data() + copy_begin,
            fragment_payload.data() + (copy_begin - begin),
            bytes);
        copied += bytes;
    }
    return copied;
}

bool ReassemblyTable::is_complete(const Slot& slot) const noexcept {
    return slot.total_length_known && slot.hole_count == 0;
}

void ReassemblyTable::release(Slot& slot) noexcept {
    slot.active = false;
    slot.hole_count = 0;
    slot.highest_received_end = 0;
    slot.total_length = 0;
    slot.total_length_known = false;
}

}  // namespace vectornet::net

#include "vectornet/transport/connection.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <utility>

#include "vectornet/alloc/packet_pool.hpp"
#include "vectornet/transport/congestion.hpp"
#include "vectornet/transport/fast_retransmit.hpp"
#include "vectornet/transport/receive_ranges.hpp"
#include "vectornet/transport/retransmission_queue.hpp"
#include "vectornet/transport/rto.hpp"
#include "vectornet/transport/sequence.hpp"
#include "vectornet/transport/wire.hpp"

namespace vectornet::transport {
namespace {

inline constexpr std::uint64_t kControlRetryNs = 1'000'000'000ULL;
inline constexpr std::uint64_t kTimeWaitNs = 2'000'000'000ULL;

[[nodiscard]] std::uint64_t deadline_from(
    std::uint64_t now_ns,
    std::uint64_t interval_ns) noexcept {
    return interval_ns > std::numeric_limits<std::uint64_t>::max() - now_ns
        ? std::numeric_limits<std::uint64_t>::max()
        : now_ns + interval_ns;
}

}  // namespace

struct Connection::Impl {
    struct ReceiveSlot {
        std::uint32_t start{0};
        std::uint32_t end{0};
        alloc::PacketBuffer* buffer{nullptr};
        bool active{false};
    };

    Impl(
        const ConnectionConfig& connection_config,
        const ConnectionCallbacks& connection_callbacks)
        : config(connection_config),
          callbacks(connection_callbacks),
          tx_pool(config.packet_pool_buffers),
          rx_pool(config.receive_capacity),
          retransmission(config.retransmission_capacity),
          receive_ranges(
              config.initial_receive_sequence, config.receive_capacity),
          fast_retransmit(config.initial_send_sequence),
          congestion(config.maximum_segment_payload_bytes),
          next_send_sequence(config.initial_send_sequence),
          oldest_unacknowledged(config.initial_send_sequence),
          delivery_sequence(config.initial_receive_sequence) {
        if (config.maximum_segment_payload_bytes == 0 ||
            config.maximum_segment_payload_bytes >
                alloc::kPacketBufferBytes - kMaximumTransportHeaderBytes) {
            config.maximum_segment_payload_bytes = static_cast<std::uint32_t>(
                alloc::kPacketBufferBytes - kMaximumTransportHeaderBytes);
        }
        config.receive_capacity = std::min(
            config.receive_capacity, kReceiveRangeCapacity);
        config.retransmission_capacity = std::min(
            config.retransmission_capacity, kRetransmissionCapacity);
    }

    ~Impl() {
        static_cast<void>(retransmission.clear(tx_pool));
        for (auto& slot : receive_slots) {
            if (slot.active) {
                static_cast<void>(rx_pool.release(slot.buffer));
                slot.active = false;
            }
        }
    }

    void notify_error(ConnectionError error) noexcept {
        if (callbacks.error != nullptr) {
            callbacks.error(callbacks.error_context, error);
        }
    }

    void notify_state() noexcept {
        if (callbacks.state != nullptr) {
            callbacks.state(callbacks.state_context, machine.state());
        }
    }

    [[nodiscard]] std::uint16_t advertised_window() const noexcept {
        const std::uint64_t bytes =
            static_cast<std::uint64_t>(rx_pool.available()) *
            config.maximum_segment_payload_bytes;
        return static_cast<std::uint16_t>(std::min<std::uint64_t>(
            bytes, std::numeric_limits<std::uint16_t>::max()));
    }

    [[nodiscard]] TransportHeader make_header(std::uint8_t flags) const noexcept {
        TransportHeader header{
            .sequence = next_send_sequence,
            .cumulative_ack = receive_ranges.cumulative_ack(),
            .flags = flags,
            .window = advertised_window(),
        };
        header.sack_count = static_cast<std::uint8_t>(
            receive_ranges.generate_sacks(header.sacks));
        return header;
    }

    [[nodiscard]] bool transmit_bytes(
        std::span<const std::byte> bytes,
        TransmitReason reason) noexcept {
        if (callbacks.transmit == nullptr) {
            ++statistics.transmit_failures;
            notify_error(ConnectionError::transmit_failed);
            return false;
        }
        const std::error_code error = callbacks.transmit(
            callbacks.transmit_context, bytes, reason);
        if (error) {
            ++statistics.transmit_failures;
            notify_error(ConnectionError::transmit_failed);
            return false;
        }
        return true;
    }

    [[nodiscard]] bool send_control(
        std::uint8_t flags,
        std::uint64_t now_ns,
        bool remember) noexcept {
        TransportHeader header = make_header(flags);
        std::size_t bytes = 0;
        if (serialize_transport_header(header, control_buffer, bytes) !=
            WireStatus::ok) {
            notify_error(ConnectionError::malformed_segment);
            return false;
        }
        if (remember) {
            remembered_control_bytes = bytes;
            remembered_control_flags = flags;
            std::copy_n(
                control_buffer.begin(), bytes, remembered_control_buffer.begin());
            control_deadline_ns = deadline_from(now_ns, kControlRetryNs);
        }
        ++statistics.control_segments_sent;
        return transmit_bytes(
            std::span<const std::byte>(control_buffer.data(), bytes),
            TransmitReason::control);
    }

    void clear_control() noexcept {
        remembered_control_bytes = 0;
        remembered_control_flags = 0;
        control_deadline_ns = 0;
    }

    [[nodiscard]] bool perform_actions(
        const TransitionResult& transition,
        std::uint64_t now_ns) noexcept {
        if (!transition.accepted) {
            notify_error(ConnectionError::invalid_transition);
        }
        std::uint8_t flags = 0;
        bool remember = false;
        if (has_action(transition.actions, ConnectionAction::send_syn)) {
            flags |= kFlagSyn;
            remember = true;
        }
        if (has_action(transition.actions, ConnectionAction::send_ack)) {
            flags |= kFlagAck;
        }
        if (has_action(transition.actions, ConnectionAction::send_fin)) {
            flags |= static_cast<std::uint8_t>(kFlagFin | kFlagAck);
            remember = true;
        }
        if (has_action(transition.actions, ConnectionAction::send_rst)) {
            flags |= kFlagRst;
        }
        bool sent = true;
        if (flags != 0) {
            sent = send_control(flags, now_ns, remember);
        }
        if (has_action(transition.actions, ConnectionAction::notify_connected) ||
            has_action(transition.actions, ConnectionAction::notify_closed)) {
            clear_control();
            notify_state();
        }
        if (has_action(transition.actions, ConnectionAction::notify_error)) {
            notify_error(ConnectionError::invalid_transition);
        }
        if (transition.current == ConnectionState::time_wait) {
            time_wait_deadline_ns = deadline_from(now_ns, kTimeWaitNs);
        }
        return transition.accepted && sent;
    }

    [[nodiscard]] bool connect(std::uint64_t now_ns) noexcept {
        const TransitionResult result = machine.handle(ConnectionEvent::app_connect);
        notify_state();
        return perform_actions(result, now_ns);
    }

    [[nodiscard]] bool close(std::uint64_t now_ns) noexcept {
        const TransitionResult result = machine.handle(ConnectionEvent::app_close);
        notify_state();
        return perform_actions(result, now_ns);
    }

    [[nodiscard]] std::uint32_t flight_bytes() const noexcept {
        return next_send_sequence - oldest_unacknowledged;
    }

    [[nodiscard]] SendStatus send(
        std::span<const std::byte> payload,
        std::uint64_t now_ns) noexcept {
        if (machine.state() != ConnectionState::established) {
            return SendStatus::closed;
        }
        if (payload.empty() ||
            payload.size() > config.maximum_segment_payload_bytes) {
            return SendStatus::payload_too_large;
        }
        if (retransmission.size() >= retransmission.capacity() ||
            congestion.send_allowance_bytes(flight_bytes(), peer_window) <
                payload.size()) {
            return SendStatus::would_block;
        }
        alloc::PacketBuffer* buffer = tx_pool.acquire();
        if (buffer == nullptr) {
            return SendStatus::would_block;
        }
        const TransportHeader header = make_header(kFlagAck);
        std::size_t header_bytes = 0;
        if (serialize_transport_header(header, buffer->data, header_bytes) !=
                WireStatus::ok ||
            header_bytes + payload.size() > buffer->data.size()) {
            static_cast<void>(tx_pool.release(buffer));
            return SendStatus::payload_too_large;
        }
        std::memcpy(
            buffer->data.data() + header_bytes, payload.data(), payload.size());
        const std::size_t segment_bytes = header_bytes + payload.size();
        buffer->length = static_cast<std::uint16_t>(segment_bytes);
        const std::uint32_t payload_bytes =
            static_cast<std::uint32_t>(payload.size());
        const PendingSegment pending{
            .sequence_start = next_send_sequence,
            .sequence_end = next_send_sequence + payload_bytes,
            .buffer = buffer,
            .sent_at_ns = now_ns,
        };
        if (retransmission.enqueue(pending) != EnqueueStatus::accepted) {
            static_cast<void>(tx_pool.release(buffer));
            return SendStatus::would_block;
        }
        next_send_sequence += payload_bytes;
        statistics.payload_bytes_sent += payload.size();
        static_cast<void>(transmit_bytes(
            std::span<const std::byte>(buffer->data.data(), buffer->length),
            TransmitReason::new_data));
        return SendStatus::accepted;
    }

    void process_ack(
        const TransportHeader& header,
        std::uint64_t now_ns) noexcept {
        peer_window = header.window;
        if (sequence_greater(header.cumulative_ack, next_send_sequence)) {
            ++statistics.malformed_segments;
            notify_error(ConnectionError::malformed_segment);
            return;
        }
        const PendingSegment* first = retransmission.at(0);
        const bool progressed = sequence_greater(
            header.cumulative_ack, oldest_unacknowledged);
        std::uint64_t sample_sent_at = 0;
        bool sample_retransmitted = false;
        if (progressed && first != nullptr &&
            sequence_less_equal(
                first->sequence_end, header.cumulative_ack)) {
            sample_sent_at = first->sent_at_ns;
            sample_retransmitted = first->retransmit_count != 0;
        }
        if (progressed) {
            const std::uint32_t acknowledged =
                header.cumulative_ack - oldest_unacknowledged;
            const AcknowledgeResult released = retransmission.acknowledge(
                header.cumulative_ack, tx_pool);
            if (released.pool_error) {
                notify_error(ConnectionError::pool_error);
            }
            oldest_unacknowledged = header.cumulative_ack;
            statistics.payload_bytes_acked += acknowledged;
            congestion.on_ack(acknowledged);
            static_cast<void>(congestion.on_recovery_ack(header.cumulative_ack));
            rto.on_forward_progress();
            if (sample_sent_at != 0) {
                static_cast<void>(rto.observe(
                    sample_sent_at, now_ns, sample_retransmitted));
            }
        }
        static_cast<void>(retransmission.apply_sacks(
            std::span<const SackBlock>(
                header.sacks.data(), header.sack_count)));
        FastRetransmitDecision decision = fast_retransmit.on_ack(
            header.cumulative_ack, now_ns, retransmission);
        if (decision.triggered && decision.segment != nullptr) {
            const PendingSegment* tail = retransmission.size() == 0
                ? nullptr
                : retransmission.at(retransmission.size() - 1);
            const std::uint32_t recovery_point =
                tail == nullptr ? next_send_sequence : tail->sequence_end;
            static_cast<void>(congestion.on_loss(
                LossSignal::sack_fast_recovery,
                flight_bytes(),
                recovery_point));
            ++statistics.fast_retransmissions;
            static_cast<void>(transmit_bytes(
                std::span<const std::byte>(
                    decision.segment->buffer->data.data(),
                    decision.segment->buffer->length),
                TransmitReason::fast_retransmit));
        }
    }

    [[nodiscard]] ReceiveSlot* free_receive_slot() noexcept {
        for (std::size_t index = 0; index < config.receive_capacity; ++index) {
            if (!receive_slots[index].active) {
                return &receive_slots[index];
            }
        }
        return nullptr;
    }

    [[nodiscard]] bool overlaps_received(
        std::uint32_t start,
        std::uint32_t end) const noexcept {
        for (std::size_t index = 0; index < config.receive_capacity; ++index) {
            const ReceiveSlot& slot = receive_slots[index];
            if (!slot.active) {
                continue;
            }
            if (sequence_less(start, slot.end) &&
                sequence_less(slot.start, end)) {
                return true;
            }
        }
        return false;
    }

    void deliver_contiguous() noexcept {
        for (;;) {
            ReceiveSlot* next = nullptr;
            for (std::size_t index = 0; index < config.receive_capacity; ++index) {
                ReceiveSlot& slot = receive_slots[index];
                if (slot.active && slot.start == delivery_sequence) {
                    next = &slot;
                    break;
                }
            }
            if (next == nullptr) {
                return;
            }
            if (callbacks.receive != nullptr) {
                callbacks.receive(
                    callbacks.receive_context,
                    std::span<const std::byte>(
                        next->buffer->data.data(), next->buffer->length));
            }
            statistics.payload_bytes_received += next->buffer->length;
            delivery_sequence = next->end;
            if (!rx_pool.release(next->buffer)) {
                notify_error(ConnectionError::pool_error);
            }
            next->active = false;
        }
    }

    void process_payload(
        const TransportHeader& header,
        std::span<const std::byte> payload,
        std::uint64_t now_ns) noexcept {
        if (payload.empty()) {
            return;
        }
        const std::uint32_t bytes = static_cast<std::uint32_t>(payload.size());
        const std::uint32_t end = header.sequence + bytes;
        if (sequence_less_equal(end, delivery_sequence) ||
            overlaps_received(header.sequence, end)) {
            ++statistics.duplicate_segments;
            static_cast<void>(send_control(kFlagAck, now_ns, false));
            return;
        }
        if (payload.size() > alloc::kPacketBufferBytes) {
            ++statistics.receive_drops;
            notify_error(ConnectionError::receive_capacity_exhausted);
            return;
        }
        ReceiveSlot* slot = free_receive_slot();
        alloc::PacketBuffer* buffer = rx_pool.acquire();
        if (slot == nullptr || buffer == nullptr) {
            if (buffer != nullptr) {
                static_cast<void>(rx_pool.release(buffer));
            }
            ++statistics.receive_drops;
            notify_error(ConnectionError::receive_capacity_exhausted);
            static_cast<void>(send_control(kFlagAck, now_ns, false));
            return;
        }
        const ReceiveRangeResult result = receive_ranges.insert(
            header.sequence, end);
        if (result.status != ReceiveRangeStatus::accepted) {
            static_cast<void>(rx_pool.release(buffer));
            if (result.status == ReceiveRangeStatus::duplicate) {
                ++statistics.duplicate_segments;
            } else {
                ++statistics.receive_drops;
            }
            static_cast<void>(send_control(kFlagAck, now_ns, false));
            return;
        }
        std::memcpy(buffer->data.data(), payload.data(), payload.size());
        buffer->length = static_cast<std::uint16_t>(payload.size());
        *slot = ReceiveSlot{
            .start = header.sequence,
            .end = end,
            .buffer = buffer,
            .active = true,
        };
        deliver_contiguous();
        static_cast<void>(send_control(kFlagAck, now_ns, false));
    }

    [[nodiscard]] bool process_control(
        const TransportHeader& header,
        std::uint64_t now_ns) noexcept {
        const bool syn = (header.flags & kFlagSyn) != 0;
        const bool ack = (header.flags & kFlagAck) != 0;
        const bool fin = (header.flags & kFlagFin) != 0;
        const bool rst = (header.flags & kFlagRst) != 0;
        if (rst) {
            return perform_actions(
                machine.handle(ConnectionEvent::receive_rst), now_ns);
        }
        if (syn && ack && machine.state() == ConnectionState::syn_sent) {
            return perform_actions(
                machine.handle(ConnectionEvent::receive_syn_ack), now_ns);
        }
        if (syn) {
            if (machine.state() == ConnectionState::syn_received) {
                return send_control(
                    static_cast<std::uint8_t>(kFlagSyn | kFlagAck),
                    now_ns,
                    true);
            }
            return perform_actions(
                machine.handle(ConnectionEvent::receive_syn), now_ns);
        }
        if (fin) {
            return perform_actions(
                machine.handle(ConnectionEvent::receive_fin), now_ns);
        }
        if (ack && machine.state() == ConnectionState::syn_received) {
            return perform_actions(
                machine.handle(ConnectionEvent::receive_ack), now_ns);
        }
        if (ack && (machine.state() == ConnectionState::fin_wait_1 ||
                    machine.state() == ConnectionState::last_ack)) {
            return perform_actions(
                machine.handle(ConnectionEvent::receive_ack), now_ns);
        }
        return true;
    }

    [[nodiscard]] bool on_segment(
        std::span<const std::byte> segment,
        std::uint64_t now_ns) noexcept {
        TransportHeader header{};
        std::size_t header_bytes = 0;
        if (parse_transport_header(segment, header, header_bytes) !=
                WireStatus::ok ||
            header_bytes > segment.size()) {
            ++statistics.malformed_segments;
            notify_error(ConnectionError::malformed_segment);
            return false;
        }
        if ((header.flags & kFlagAck) != 0) {
            process_ack(header, now_ns);
        }
        if (!process_control(header, now_ns)) {
            return false;
        }
        const std::span<const std::byte> payload = segment.subspan(header_bytes);
        if (!payload.empty()) {
            if (machine.state() != ConnectionState::established) {
                notify_error(ConnectionError::invalid_transition);
                return false;
            }
            process_payload(header, payload, now_ns);
        }
        return true;
    }

    void tick(std::uint64_t now_ns) noexcept {
        if (machine.state() == ConnectionState::time_wait &&
            time_wait_deadline_ns != 0 && now_ns >= time_wait_deadline_ns) {
            static_cast<void>(perform_actions(
                machine.handle(ConnectionEvent::time_wait_expired), now_ns));
        }
        if (remembered_control_bytes != 0 && now_ns >= control_deadline_ns) {
            control_deadline_ns = deadline_from(now_ns, kControlRetryNs);
            ++statistics.control_segments_sent;
            static_cast<void>(transmit_bytes(
                std::span<const std::byte>(
                    remembered_control_buffer.data(), remembered_control_bytes),
                TransmitReason::control));
        }
        PendingSegment* segment = retransmission.lowest_unsacked();
        if (segment == nullptr || now_ns < segment->sent_at_ns ||
            now_ns - segment->sent_at_ns < rto.rto_ns()) {
            return;
        }
        const PendingSegment* tail = retransmission.at(
            retransmission.size() - 1);
        const std::uint32_t recovery_point =
            tail == nullptr ? next_send_sequence : tail->sequence_end;
        static_cast<void>(congestion.on_loss(
            LossSignal::rto_timeout, flight_bytes(), recovery_point));
        if (segment->retransmit_count !=
            std::numeric_limits<std::uint16_t>::max()) {
            ++segment->retransmit_count;
        }
        segment->sent_at_ns = now_ns;
        static_cast<void>(rto.on_timeout());
        ++statistics.rto_retransmissions;
        static_cast<void>(transmit_bytes(
            std::span<const std::byte>(
                segment->buffer->data.data(), segment->buffer->length),
            TransmitReason::rto_retransmit));
    }

    ConnectionConfig config;
    ConnectionCallbacks callbacks;
    alloc::PacketPool tx_pool;
    alloc::PacketPool rx_pool;
    ConnectionStateMachine machine{};
    RetransmissionQueue retransmission;
    ReceiveRangeSet receive_ranges;
    FastRetransmitController fast_retransmit;
    RtoEstimator rto{};
    CongestionController congestion;
    std::array<ReceiveSlot, kReceiveRangeCapacity> receive_slots{};
    std::array<std::byte, kMaximumTransportHeaderBytes> control_buffer{};
    std::array<std::byte, kMaximumTransportHeaderBytes> remembered_control_buffer{};
    std::uint32_t next_send_sequence{0};
    std::uint32_t oldest_unacknowledged{0};
    std::uint32_t delivery_sequence{0};
    std::uint16_t peer_window{std::numeric_limits<std::uint16_t>::max()};
    std::size_t remembered_control_bytes{0};
    std::uint8_t remembered_control_flags{0};
    std::uint64_t control_deadline_ns{0};
    std::uint64_t time_wait_deadline_ns{0};
    ConnectionStatistics statistics{};
};

Connection::Connection(
    const ConnectionConfig& config,
    const ConnectionCallbacks& callbacks)
    : impl_(std::make_unique<Impl>(config, callbacks)) {}

Connection::Connection(Connection&&) noexcept = default;
Connection& Connection::operator=(Connection&&) noexcept = default;
Connection::~Connection() = default;

bool Connection::connect(std::uint64_t now_ns) noexcept {
    return impl_->connect(now_ns);
}

SendStatus Connection::send(
    std::span<const std::byte> payload,
    std::uint64_t now_ns) noexcept {
    return impl_->send(payload, now_ns);
}

bool Connection::close(std::uint64_t now_ns) noexcept {
    return impl_->close(now_ns);
}

bool Connection::on_segment(
    std::span<const std::byte> segment,
    std::uint64_t now_ns) noexcept {
    return impl_->on_segment(segment, now_ns);
}

void Connection::tick(std::uint64_t now_ns) noexcept {
    impl_->tick(now_ns);
}

ConnectionState Connection::state() const noexcept {
    return impl_->machine.state();
}

ConnectionStatistics Connection::statistics() const noexcept {
    return impl_->statistics;
}

std::uint32_t Connection::congestion_window_bytes() const noexcept {
    return impl_->congestion.congestion_window_bytes();
}

std::uint64_t Connection::retransmission_timeout_ns() const noexcept {
    return impl_->rto.rto_ns();
}

}  // namespace vectornet::transport

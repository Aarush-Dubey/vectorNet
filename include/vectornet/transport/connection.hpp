#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>

#include "vectornet/transport/state_machine.hpp"

namespace vectornet::transport {

enum class SendStatus : std::uint8_t {
    accepted,
    would_block,
    closed,
    payload_too_large,
};

enum class ConnectionError : std::uint8_t {
    malformed_segment,
    invalid_transition,
    transmit_failed,
    receive_capacity_exhausted,
    pool_error,
};

enum class TransmitReason : std::uint8_t {
    control,
    new_data,
    fast_retransmit,
    rto_retransmit,
};

struct ConnectionConfig {
    std::uint32_t initial_send_sequence{0};
    std::uint32_t initial_receive_sequence{0};
    std::uint32_t maximum_segment_payload_bytes{1'436};
    std::size_t packet_pool_buffers{4'096};
    std::size_t retransmission_capacity{1'024};
    std::size_t receive_capacity{1'024};
};

using SegmentTransmitCallback = std::error_code (*)(
    void* context,
    std::span<const std::byte> segment,
    TransmitReason reason) noexcept;

using ReceiveCallback = void (*)(
    void* context,
    std::span<const std::byte> payload) noexcept;

using StateCallback = void (*)(
    void* context,
    ConnectionState state) noexcept;

using ErrorCallback = void (*)(
    void* context,
    ConnectionError error) noexcept;

struct ConnectionCallbacks {
    SegmentTransmitCallback transmit{nullptr};
    void* transmit_context{nullptr};
    ReceiveCallback receive{nullptr};
    void* receive_context{nullptr};
    StateCallback state{nullptr};
    void* state_context{nullptr};
    ErrorCallback error{nullptr};
    void* error_context{nullptr};
};

struct ConnectionStatistics {
    std::uint64_t payload_bytes_sent{0};
    std::uint64_t payload_bytes_acked{0};
    std::uint64_t payload_bytes_received{0};
    std::uint64_t control_segments_sent{0};
    std::uint64_t malformed_segments{0};
    std::uint64_t duplicate_segments{0};
    std::uint64_t fast_retransmissions{0};
    std::uint64_t rto_retransmissions{0};
    std::uint64_t transmit_failures{0};
    std::uint64_t receive_drops{0};
};

class Connection final {
public:
    explicit Connection(
        const ConnectionConfig& config,
        const ConnectionCallbacks& callbacks);
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&&) noexcept;
    Connection& operator=(Connection&&) noexcept;
    ~Connection();

    [[nodiscard]] bool connect(std::uint64_t now_ns) noexcept;
    [[nodiscard]] SendStatus send(
        std::span<const std::byte> payload,
        std::uint64_t now_ns) noexcept;
    [[nodiscard]] bool close(std::uint64_t now_ns) noexcept;

    [[nodiscard]] bool on_segment(
        std::span<const std::byte> segment,
        std::uint64_t now_ns) noexcept;
    void tick(std::uint64_t now_ns) noexcept;

    [[nodiscard]] ConnectionState state() const noexcept;
    [[nodiscard]] ConnectionStatistics statistics() const noexcept;
    [[nodiscard]] std::uint32_t congestion_window_bytes() const noexcept;
    [[nodiscard]] std::uint64_t retransmission_timeout_ns() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace vectornet::transport

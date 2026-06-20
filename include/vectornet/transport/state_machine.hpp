#pragma once

#include <cstdint>

namespace vectornet::transport {

enum class ConnectionState : std::uint8_t {
    closed,
    syn_sent,
    syn_received,
    established,
    fin_wait_1,
    fin_wait_2,
    close_wait,
    last_ack,
    time_wait,
    count,
};

enum class ConnectionEvent : std::uint8_t {
    app_connect,
    app_close,
    receive_syn,
    receive_syn_ack,
    receive_ack,
    receive_fin,
    receive_rst,
    time_wait_expired,
    count,
};

enum class ConnectionAction : std::uint16_t {
    none = 0,
    send_syn = 1U << 0U,
    send_ack = 1U << 1U,
    send_fin = 1U << 2U,
    send_rst = 1U << 3U,
    notify_connected = 1U << 4U,
    notify_closed = 1U << 5U,
    notify_error = 1U << 6U,
};

[[nodiscard]] constexpr ConnectionAction operator|(
    ConnectionAction left,
    ConnectionAction right) noexcept {
    return static_cast<ConnectionAction>(
        static_cast<std::uint16_t>(left) |
        static_cast<std::uint16_t>(right));
}

[[nodiscard]] constexpr bool has_action(
    ConnectionAction actions,
    ConnectionAction action) noexcept {
    return (static_cast<std::uint16_t>(actions) &
            static_cast<std::uint16_t>(action)) != 0;
}

struct TransitionResult {
    ConnectionState previous{ConnectionState::closed};
    ConnectionState current{ConnectionState::closed};
    ConnectionAction actions{ConnectionAction::none};
    bool accepted{false};
};

class ConnectionStateMachine final {
public:
    [[nodiscard]] TransitionResult handle(ConnectionEvent event) noexcept;
    [[nodiscard]] ConnectionState state() const noexcept;

private:
    ConnectionState state_{ConnectionState::closed};
    bool reset_sent_{false};
};

}  // namespace vectornet::transport

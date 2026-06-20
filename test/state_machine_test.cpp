#include "vectornet/transport/state_machine.hpp"

#include <array>
#include <cstddef>
#include <iostream>

namespace {

using vectornet::transport::ConnectionAction;
using vectornet::transport::ConnectionEvent;
using vectornet::transport::ConnectionState;
using vectornet::transport::ConnectionStateMachine;

struct Expected {
    ConnectionState state;
    ConnectionEvent event;
    ConnectionState next;
};

constexpr std::array<Expected, 23> kExpected{{
    {ConnectionState::closed, ConnectionEvent::app_connect, ConnectionState::syn_sent},
    {ConnectionState::closed, ConnectionEvent::receive_syn, ConnectionState::syn_received},
    {ConnectionState::syn_sent, ConnectionEvent::receive_syn, ConnectionState::syn_received},
    {ConnectionState::syn_sent, ConnectionEvent::receive_syn_ack, ConnectionState::established},
    {ConnectionState::syn_received, ConnectionEvent::receive_ack, ConnectionState::established},
    {ConnectionState::established, ConnectionEvent::app_close, ConnectionState::fin_wait_1},
    {ConnectionState::established, ConnectionEvent::receive_fin, ConnectionState::close_wait},
    {ConnectionState::fin_wait_1, ConnectionEvent::receive_ack, ConnectionState::fin_wait_2},
    {ConnectionState::fin_wait_1, ConnectionEvent::receive_fin, ConnectionState::time_wait},
    {ConnectionState::fin_wait_2, ConnectionEvent::receive_fin, ConnectionState::time_wait},
    {ConnectionState::close_wait, ConnectionEvent::app_close, ConnectionState::last_ack},
    {ConnectionState::last_ack, ConnectionEvent::receive_ack, ConnectionState::closed},
    {ConnectionState::time_wait, ConnectionEvent::time_wait_expired, ConnectionState::closed},
    {ConnectionState::syn_sent, ConnectionEvent::receive_rst, ConnectionState::closed},
    {ConnectionState::syn_received, ConnectionEvent::receive_rst, ConnectionState::closed},
    {ConnectionState::established, ConnectionEvent::receive_rst, ConnectionState::closed},
    {ConnectionState::fin_wait_1, ConnectionEvent::receive_rst, ConnectionState::closed},
    {ConnectionState::fin_wait_2, ConnectionEvent::receive_rst, ConnectionState::closed},
    {ConnectionState::close_wait, ConnectionEvent::receive_rst, ConnectionState::closed},
    {ConnectionState::last_ack, ConnectionEvent::receive_rst, ConnectionState::closed},
    {ConnectionState::time_wait, ConnectionEvent::receive_rst, ConnectionState::closed},
    {ConnectionState::closed, ConnectionEvent::receive_rst, ConnectionState::closed},
    {ConnectionState::closed, ConnectionEvent::time_wait_expired, ConnectionState::closed},
}};

[[nodiscard]] const Expected* expected(
    ConnectionState state,
    ConnectionEvent event) {
    for (const auto& transition : kExpected) {
        if (transition.state == state && transition.event == event) {
            return &transition;
        }
    }
    return nullptr;
}

[[nodiscard]] bool drive_to(ConnectionState target, ConnectionStateMachine& machine) {
    using E = ConnectionEvent;
    switch (target) {
    case ConnectionState::closed:
        return true;
    case ConnectionState::syn_sent:
        return machine.handle(E::app_connect).accepted;
    case ConnectionState::syn_received:
        return machine.handle(E::receive_syn).accepted;
    case ConnectionState::established:
        return machine.handle(E::app_connect).accepted &&
            machine.handle(E::receive_syn_ack).accepted;
    case ConnectionState::fin_wait_1:
        return drive_to(ConnectionState::established, machine) &&
            machine.handle(E::app_close).accepted;
    case ConnectionState::fin_wait_2:
        return drive_to(ConnectionState::fin_wait_1, machine) &&
            machine.handle(E::receive_ack).accepted;
    case ConnectionState::close_wait:
        return drive_to(ConnectionState::established, machine) &&
            machine.handle(E::receive_fin).accepted;
    case ConnectionState::last_ack:
        return drive_to(ConnectionState::close_wait, machine) &&
            machine.handle(E::app_close).accepted;
    case ConnectionState::time_wait:
        return drive_to(ConnectionState::fin_wait_2, machine) &&
            machine.handle(E::receive_fin).accepted;
    case ConnectionState::count:
        return false;
    }
    return false;
}

}  // namespace

int main() {
    for (std::size_t state_value = 0;
         state_value < static_cast<std::size_t>(ConnectionState::count);
         ++state_value) {
        const auto state = static_cast<ConnectionState>(state_value);
        for (std::size_t event_value = 0;
             event_value < static_cast<std::size_t>(ConnectionEvent::count);
             ++event_value) {
            const auto event = static_cast<ConnectionEvent>(event_value);
            ConnectionStateMachine machine;
            if (!drive_to(state, machine) || machine.state() != state) {
                std::cerr << "failed to construct source state\n";
                return 1;
            }
            const auto result = machine.handle(event);
            const Expected* transition = expected(state, event);
            if (transition != nullptr) {
                if (!result.accepted || result.current != transition->next) {
                    std::cerr << "valid transition rejected\n";
                    return 1;
                }
                continue;
            }
            if (result.accepted || result.current != ConnectionState::closed ||
                !vectornet::transport::has_action(
                    result.actions, ConnectionAction::notify_error) ||
                !vectornet::transport::has_action(
                    result.actions, ConnectionAction::send_rst)) {
                std::cerr << "invalid transition not rejected/reset/notified\n";
                return 1;
            }
            const auto repeated = machine.handle(ConnectionEvent::receive_ack);
            if (repeated.accepted ||
                vectornet::transport::has_action(
                    repeated.actions, ConnectionAction::send_rst)) {
                std::cerr << "invalid transition emitted repeated RST\n";
                return 1;
            }
        }
    }
    return 0;
}

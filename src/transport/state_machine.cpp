#include "vectornet/transport/state_machine.hpp"

#include <array>

namespace vectornet::transport {
namespace {

struct Transition {
    ConnectionState from;
    ConnectionEvent event;
    ConnectionState to;
    ConnectionAction actions;
};

constexpr ConnectionAction kSynAck =
    ConnectionAction::send_syn | ConnectionAction::send_ack;
constexpr ConnectionAction kCloseError =
    ConnectionAction::notify_error | ConnectionAction::notify_closed;

constexpr std::array<Transition, 23> kTransitions{{
    {ConnectionState::closed, ConnectionEvent::app_connect,
     ConnectionState::syn_sent, ConnectionAction::send_syn},
    {ConnectionState::closed, ConnectionEvent::receive_syn,
     ConnectionState::syn_received, kSynAck},
    {ConnectionState::syn_sent, ConnectionEvent::receive_syn,
     ConnectionState::syn_received, kSynAck},
    {ConnectionState::syn_sent, ConnectionEvent::receive_syn_ack,
     ConnectionState::established,
     ConnectionAction::send_ack | ConnectionAction::notify_connected},
    {ConnectionState::syn_received, ConnectionEvent::receive_ack,
     ConnectionState::established, ConnectionAction::notify_connected},
    {ConnectionState::established, ConnectionEvent::app_close,
     ConnectionState::fin_wait_1, ConnectionAction::send_fin},
    {ConnectionState::established, ConnectionEvent::receive_fin,
     ConnectionState::close_wait, ConnectionAction::send_ack},
    {ConnectionState::fin_wait_1, ConnectionEvent::receive_ack,
     ConnectionState::fin_wait_2, ConnectionAction::none},
    {ConnectionState::fin_wait_1, ConnectionEvent::receive_fin,
     ConnectionState::time_wait, ConnectionAction::send_ack},
    {ConnectionState::fin_wait_2, ConnectionEvent::receive_fin,
     ConnectionState::time_wait, ConnectionAction::send_ack},
    {ConnectionState::close_wait, ConnectionEvent::app_close,
     ConnectionState::last_ack, ConnectionAction::send_fin},
    {ConnectionState::last_ack, ConnectionEvent::receive_ack,
     ConnectionState::closed, ConnectionAction::notify_closed},
    {ConnectionState::time_wait, ConnectionEvent::time_wait_expired,
     ConnectionState::closed, ConnectionAction::notify_closed},
    {ConnectionState::syn_sent, ConnectionEvent::receive_rst,
     ConnectionState::closed, kCloseError},
    {ConnectionState::syn_received, ConnectionEvent::receive_rst,
     ConnectionState::closed, kCloseError},
    {ConnectionState::established, ConnectionEvent::receive_rst,
     ConnectionState::closed, kCloseError},
    {ConnectionState::fin_wait_1, ConnectionEvent::receive_rst,
     ConnectionState::closed, kCloseError},
    {ConnectionState::fin_wait_2, ConnectionEvent::receive_rst,
     ConnectionState::closed, kCloseError},
    {ConnectionState::close_wait, ConnectionEvent::receive_rst,
     ConnectionState::closed, kCloseError},
    {ConnectionState::last_ack, ConnectionEvent::receive_rst,
     ConnectionState::closed, kCloseError},
    {ConnectionState::time_wait, ConnectionEvent::receive_rst,
     ConnectionState::closed, kCloseError},
    {ConnectionState::closed, ConnectionEvent::receive_rst,
     ConnectionState::closed, ConnectionAction::notify_error},
    {ConnectionState::closed, ConnectionEvent::time_wait_expired,
     ConnectionState::closed, ConnectionAction::none},
}};

}  // namespace

TransitionResult ConnectionStateMachine::handle(ConnectionEvent event) noexcept {
    const ConnectionState previous = state_;
    for (const auto& transition : kTransitions) {
        if (transition.from != state_ || transition.event != event) {
            continue;
        }
        state_ = transition.to;
        if (previous == ConnectionState::closed &&
            (event == ConnectionEvent::app_connect ||
             event == ConnectionEvent::receive_syn)) {
            reset_sent_ = false;
        }
        return {
            .previous = previous,
            .current = state_,
            .actions = transition.actions,
            .accepted = true,
        };
    }

    ConnectionAction actions = ConnectionAction::notify_error;
    if (!reset_sent_) {
        actions = actions | ConnectionAction::send_rst;
        reset_sent_ = true;
    }
    state_ = ConnectionState::closed;
    return {
        .previous = previous,
        .current = state_,
        .actions = actions,
        .accepted = false,
    };
}

ConnectionState ConnectionStateMachine::state() const noexcept {
    return state_;
}

}  // namespace vectornet::transport

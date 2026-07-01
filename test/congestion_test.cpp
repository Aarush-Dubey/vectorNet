#include "vectornet/transport/congestion.hpp"

#include <cstdint>
#include <iostream>

namespace {

[[nodiscard]] bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

}  // namespace

int main() {
    using namespace vectornet::transport;
    constexpr std::uint32_t mss = 1'000;
    CongestionController controller(mss, 20'000);
    if (!expect(controller.congestion_window_bytes() == 10'000,
                "initial cwnd is not ten MSS") ||
        !expect(controller.state() == CongestionState::slow_start,
                "initial state is not slow start")) {
        return 1;
    }
    for (std::uint32_t ack = 0; ack < 10; ++ack) {
        controller.on_ack(mss);
        if (!expect(controller.congestion_window_bytes() == 11'000 + ack * mss,
                    "slow-start trace mismatch")) {
            return 1;
        }
    }
    if (!expect(controller.congestion_window_bytes() == 20'000,
                "slow start did not reach threshold") ||
        !expect(controller.state() == CongestionState::congestion_avoidance,
                "threshold did not enter congestion avoidance")) {
        return 1;
    }
    for (std::uint32_t ack = 0; ack < 19; ++ack) {
        controller.on_ack(mss);
        if (!expect(controller.congestion_window_bytes() == 20'000,
                    "additive increase occurred before one cwnd ACKed")) {
            return 1;
        }
    }
    controller.on_ack(mss);
    if (!expect(controller.congestion_window_bytes() == 21'000,
                "additive increase did not add one MSS per RTT") ||
        !expect(controller.effective_window_bytes(15'000) == 15'000,
                "advertised window did not cap cwnd") ||
        !expect(controller.send_allowance_bytes(14'000, 15'000) == 1'000,
                "send allowance mismatch") ||
        !expect(controller.send_allowance_bytes(15'000, 15'000) == 0,
                "full flight did not block send")) {
        return 1;
    }

    CongestionController fast(mss, 20'000);
    CongestionController timeout(mss, 20'000);
    for (std::uint32_t ack = 0; ack < 10; ++ack) {
        fast.on_ack(mss);
        timeout.on_ack(mss);
    }
    const auto fast_loss = fast.on_loss(
        LossSignal::sack_fast_recovery, 18'000, 50'000);
    const auto timeout_loss = timeout.on_loss(
        LossSignal::rto_timeout, 18'000, 50'000);
    if (!expect(fast_loss.applied && fast_loss.slow_start_threshold_bytes == 9'000,
                "fast-loss threshold mismatch") ||
        !expect(fast_loss.congestion_window_bytes == 9'000 &&
                    fast_loss.state == CongestionState::congestion_avoidance,
                "fast-loss trajectory mismatch") ||
        !expect(timeout_loss.applied &&
                    timeout_loss.slow_start_threshold_bytes == 9'000,
                "RTO-loss threshold mismatch") ||
        !expect(timeout_loss.congestion_window_bytes == 1'000 &&
                    timeout_loss.state == CongestionState::slow_start,
                "RTO-loss trajectory mismatch")) {
        return 1;
    }
    const auto repeated = fast.on_loss(
        LossSignal::sack_fast_recovery, 9'000, 60'000);
    if (!expect(!repeated.applied && fast.congestion_window_bytes() == 9'000,
                "recovery epoch applied repeated decrease") ||
        !expect(!fast.on_recovery_ack(49'999),
                "ACK below recovery point ended epoch") ||
        !expect(fast.on_recovery_ack(50'000) && !fast.in_recovery(),
                "ACK at recovery point did not end epoch")) {
        return 1;
    }
    return expect(fast.on_loss(
                      LossSignal::sack_fast_recovery, 8'000, 70'000).applied,
                  "new recovery epoch did not permit loss response")
               ? 0
               : 1;
}

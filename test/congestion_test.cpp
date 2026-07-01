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
    return expect(controller.congestion_window_bytes() == 21'000,
                  "additive increase did not add one MSS per RTT") &&
                   expect(controller.effective_window_bytes(15'000) == 15'000,
                          "advertised window did not cap cwnd") &&
                   expect(controller.send_allowance_bytes(14'000, 15'000) == 1'000,
                          "send allowance mismatch") &&
                   expect(controller.send_allowance_bytes(15'000, 15'000) == 0,
                          "full flight did not block send")
               ? 0
               : 1;
}

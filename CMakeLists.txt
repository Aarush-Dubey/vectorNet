cmake_minimum_required(VERSION 3.25)

if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "Minimum supported macOS version")
endif()

project(vectorNet VERSION 0.1.0 LANGUAGES CXX)

if(NOT APPLE)
    message(FATAL_ERROR "vectorNet supports macOS/Darwin only")
endif()

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
    message(FATAL_ERROR "vectorNet supports Apple Silicon only")
endif()

include(CTest)
option(VECTORNET_BUILD_FUZZERS "Build sanitizer-backed libFuzzer targets" OFF)
option(VECTORNET_ENABLE_TSAN "Instrument the Phase 12 handoff gate with TSan" OFF)

add_library(vectornet_alloc STATIC
    src/alloc/packet_pool.cpp
)
add_library(vectornet::alloc ALIAS vectornet_alloc)
target_compile_features(vectornet_alloc PUBLIC cxx_std_20)
target_include_directories(vectornet_alloc
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_options(vectornet_alloc PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)
if(VECTORNET_ENABLE_TSAN)
    target_compile_options(vectornet_alloc PRIVATE
        -fsanitize=thread
        -fno-omit-frame-pointer
    )
endif()

add_library(vectornet_link STATIC
    src/link/arp.cpp
    src/link/ethernet.cpp
    src/link/link_endpoint.cpp
    src/link/darwin/bpf_backend.cpp
)

add_library(vectornet::link ALIAS vectornet_link)

target_compile_features(vectornet_link PUBLIC cxx_std_20)
target_compile_definitions(vectornet_link PRIVATE VECTORNET_PLATFORM_DARWIN=1)
target_include_directories(vectornet_link
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_options(vectornet_link PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)

add_library(vectornet_net STATIC
    src/net/fragmentation.cpp
    src/net/ipv4.cpp
    src/net/reassembly.cpp
)
add_library(vectornet::net ALIAS vectornet_net)
target_compile_features(vectornet_net PUBLIC cxx_std_20)
target_include_directories(vectornet_net
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_options(vectornet_net PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)

if(VECTORNET_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "^(AppleClang|Clang)$")
        message(FATAL_ERROR "VECTORNET_BUILD_FUZZERS requires Clang")
    endif()
    target_compile_options(vectornet_net PRIVATE
        -fsanitize=address,undefined,fuzzer-no-link
        -fno-omit-frame-pointer
    )
endif()

add_library(vectornet_transport STATIC
    src/transport/fast_retransmit.cpp
    src/transport/receive_ranges.cpp
    src/transport/retransmission_queue.cpp
    src/transport/state_machine.cpp
    src/transport/wire.cpp
)
add_library(vectornet::transport ALIAS vectornet_transport)
target_compile_features(vectornet_transport PUBLIC cxx_std_20)
target_include_directories(vectornet_transport
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(vectornet_transport PUBLIC vectornet::alloc)
target_compile_options(vectornet_transport PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)

add_executable(vectornet_link_probe tools/link_probe.cpp)
target_compile_features(vectornet_link_probe PRIVATE cxx_std_20)
target_link_libraries(vectornet_link_probe PRIVATE vectornet::link)
target_compile_options(vectornet_link_probe PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)

add_executable(vectornet_ndrv_probe tools/ndrv_probe.cpp)
target_compile_features(vectornet_ndrv_probe PRIVATE cxx_std_20)
target_compile_options(vectornet_ndrv_probe PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)

add_executable(vectornet_batch_probe tools/link_batch_probe.cpp)
target_compile_features(vectornet_batch_probe PRIVATE cxx_std_20)
target_link_libraries(vectornet_batch_probe PRIVATE vectornet::link)
target_compile_options(vectornet_batch_probe PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)

add_executable(vectornet_ethernet_probe tools/ethernet_probe.cpp)
target_compile_features(vectornet_ethernet_probe PRIVATE cxx_std_20)
target_link_libraries(vectornet_ethernet_probe PRIVATE vectornet::link)
target_compile_options(vectornet_ethernet_probe PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)

add_executable(vectornet_fragment_probe tools/fragment_probe.cpp)
target_compile_features(vectornet_fragment_probe PRIVATE cxx_std_20)
target_link_libraries(vectornet_fragment_probe PRIVATE vectornet::net)
target_compile_options(vectornet_fragment_probe PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)

add_executable(vectornet_packet_pool_bench tools/packet_pool_bench.cpp)
target_compile_features(vectornet_packet_pool_bench PRIVATE cxx_std_20)
target_link_libraries(vectornet_packet_pool_bench PRIVATE vectornet::alloc)
target_compile_options(vectornet_packet_pool_bench PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)

add_library(vectornet_alloc_interposer SHARED test/alloc_interposer.cpp)
target_compile_features(vectornet_alloc_interposer PRIVATE cxx_std_20)
target_compile_options(vectornet_alloc_interposer PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

if(VECTORNET_BUILD_FUZZERS)
    add_executable(vectornet_reassembly_fuzzer test/fuzz/reassembly_fuzz.cpp)
    target_compile_features(vectornet_reassembly_fuzzer PRIVATE cxx_std_20)
    target_link_libraries(vectornet_reassembly_fuzzer PRIVATE vectornet::net)
    target_compile_options(vectornet_reassembly_fuzzer PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -fsanitize=address,undefined,fuzzer
        -fno-omit-frame-pointer
    )
    target_link_options(vectornet_reassembly_fuzzer PRIVATE
        -fsanitize=address,undefined,fuzzer
    )
endif()

if(BUILD_TESTING)
    add_executable(vectornet_scaffold_test test/scaffold_test.cpp)
    target_compile_features(vectornet_scaffold_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_scaffold_test PRIVATE vectornet::link)
    target_compile_options(vectornet_scaffold_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.scaffold COMMAND vectornet_scaffold_test)

    add_executable(vectornet_ethernet_test test/ethernet_test.cpp)
    target_compile_features(vectornet_ethernet_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_ethernet_test PRIVATE vectornet::link)
    target_compile_options(vectornet_ethernet_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.ethernet COMMAND vectornet_ethernet_test)

    add_executable(vectornet_arp_test test/arp_test.cpp)
    target_compile_features(vectornet_arp_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_arp_test PRIVATE vectornet::link)
    target_compile_options(vectornet_arp_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.arp COMMAND vectornet_arp_test)

    add_executable(vectornet_arp_pending_test test/arp_pending_test.cpp)
    target_compile_features(vectornet_arp_pending_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_arp_pending_test PRIVATE vectornet::link)
    target_compile_options(vectornet_arp_pending_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.arp_pending COMMAND vectornet_arp_pending_test)

    add_executable(vectornet_ipv4_test test/ipv4_test.cpp)
    target_compile_features(vectornet_ipv4_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_ipv4_test PRIVATE vectornet::net)
    target_compile_options(vectornet_ipv4_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.ipv4 COMMAND vectornet_ipv4_test)

    add_executable(vectornet_fragmentation_test test/fragmentation_test.cpp)
    target_compile_features(vectornet_fragmentation_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_fragmentation_test PRIVATE vectornet::net)
    target_compile_options(vectornet_fragmentation_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.fragmentation COMMAND vectornet_fragmentation_test)

    add_executable(vectornet_reassembly_test test/reassembly_test.cpp)
    target_compile_features(vectornet_reassembly_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_reassembly_test PRIVATE vectornet::net)
    target_compile_options(vectornet_reassembly_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.reassembly COMMAND vectornet_reassembly_test)

    add_executable(vectornet_packet_pool_test test/packet_pool_test.cpp)
    target_compile_features(vectornet_packet_pool_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_packet_pool_test PRIVATE vectornet::alloc)
    target_compile_options(vectornet_packet_pool_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.packet_pool COMMAND vectornet_packet_pool_test)

    add_executable(vectornet_spsc_ring_test test/spsc_ring_test.cpp)
    target_compile_features(vectornet_spsc_ring_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_spsc_ring_test PRIVATE vectornet::alloc)
    target_compile_options(vectornet_spsc_ring_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.spsc_ring COMMAND vectornet_spsc_ring_test)

    add_executable(vectornet_spsc_stress test/spsc_stress.cpp)
    target_compile_features(vectornet_spsc_stress PRIVATE cxx_std_20)
    target_link_libraries(vectornet_spsc_stress PRIVATE vectornet::alloc)
    target_compile_options(vectornet_spsc_stress PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    if(VECTORNET_ENABLE_TSAN)
        target_compile_options(vectornet_spsc_stress PRIVATE
            -fsanitize=thread
            -fno-omit-frame-pointer
        )
        target_link_options(vectornet_spsc_stress PRIVATE -fsanitize=thread)
    endif()
    add_test(NAME vectornet.spsc_stress COMMAND vectornet_spsc_stress)

    add_executable(vectornet_transport_wire_test test/transport_wire_test.cpp)
    target_compile_features(vectornet_transport_wire_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_transport_wire_test PRIVATE vectornet::transport)
    target_compile_options(vectornet_transport_wire_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.transport_wire COMMAND vectornet_transport_wire_test)

    add_executable(vectornet_state_machine_test test/state_machine_test.cpp)
    target_compile_features(vectornet_state_machine_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_state_machine_test PRIVATE vectornet::transport)
    target_compile_options(vectornet_state_machine_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.state_machine COMMAND vectornet_state_machine_test)

    add_executable(
        vectornet_retransmission_queue_test
        test/retransmission_queue_test.cpp
    )
    target_compile_features(vectornet_retransmission_queue_test PRIVATE cxx_std_20)
    target_link_libraries(
        vectornet_retransmission_queue_test
        PRIVATE vectornet::transport
    )
    target_compile_options(vectornet_retransmission_queue_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(
        NAME vectornet.retransmission_queue
        COMMAND vectornet_retransmission_queue_test
    )

    add_executable(vectornet_receive_ranges_test test/receive_ranges_test.cpp)
    target_compile_features(vectornet_receive_ranges_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_receive_ranges_test PRIVATE vectornet::transport)
    target_compile_options(vectornet_receive_ranges_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.receive_ranges COMMAND vectornet_receive_ranges_test)

    add_executable(vectornet_fast_retransmit_test test/fast_retransmit_test.cpp)
    target_compile_features(vectornet_fast_retransmit_test PRIVATE cxx_std_20)
    target_link_libraries(vectornet_fast_retransmit_test PRIVATE vectornet::transport)
    target_compile_options(vectornet_fast_retransmit_test PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
    add_test(NAME vectornet.fast_retransmit COMMAND vectornet_fast_retransmit_test)
endif()

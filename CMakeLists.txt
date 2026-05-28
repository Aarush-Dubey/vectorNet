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
endif()

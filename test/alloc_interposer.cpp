#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

namespace {

enum Counter : std::size_t {
    malloc_call,
    calloc_call,
    realloc_call,
    free_call,
    new_call,
    new_array_call,
    delete_call,
    delete_array_call,
    counter_count,
};

std::atomic<bool> gate_active{false};
std::atomic<std::uint64_t> counters[counter_count]{};

void count(Counter counter) noexcept {
    if (gate_active.load(std::memory_order_relaxed)) {
        counters[counter].fetch_add(1, std::memory_order_relaxed);
    }
}

extern "C" void* counted_malloc(std::size_t bytes) {
    count(malloc_call);
    return std::malloc(bytes);
}

extern "C" void* counted_calloc(std::size_t count_value, std::size_t bytes) {
    count(calloc_call);
    return std::calloc(count_value, bytes);
}

extern "C" void* counted_realloc(void* pointer, std::size_t bytes) {
    count(realloc_call);
    return std::realloc(pointer, bytes);
}

extern "C" void counted_free(void* pointer) {
    count(free_call);
    std::free(pointer);
}

extern "C" void* counted_cpp_new(std::size_t bytes) {
    count(new_call);
    return ::operator new(bytes);
}

extern "C" void* counted_cpp_new_array(std::size_t bytes) {
    count(new_array_call);
    return ::operator new[](bytes);
}

extern "C" void counted_cpp_delete(void* pointer) {
    count(delete_call);
    ::operator delete(pointer);
}

extern "C" void counted_cpp_delete_array(void* pointer) {
    count(delete_array_call);
    ::operator delete[](pointer);
}

#define VECTORNET_DYLD_INTERPOSE(replacement, replacee, suffix)                 \
    __attribute__((used)) static const struct {                                \
        const void* replacement_address;                                       \
        const void* replacee_address;                                           \
    } vectornet_interpose_##suffix                                              \
        __attribute__((section("__DATA,__interpose"))) = {                      \
            reinterpret_cast<const void*>(replacement),                        \
            reinterpret_cast<const void*>(replacee),                           \
        }

VECTORNET_DYLD_INTERPOSE(counted_malloc, malloc, malloc);
VECTORNET_DYLD_INTERPOSE(counted_calloc, calloc, calloc);
VECTORNET_DYLD_INTERPOSE(counted_realloc, realloc, realloc);
VECTORNET_DYLD_INTERPOSE(counted_free, free, free);
VECTORNET_DYLD_INTERPOSE(
    counted_cpp_new,
    static_cast<void* (*)(std::size_t)>(&::operator new),
    cpp_new);
VECTORNET_DYLD_INTERPOSE(
    counted_cpp_new_array,
    static_cast<void* (*)(std::size_t)>(&::operator new[]),
    cpp_new_array);
VECTORNET_DYLD_INTERPOSE(
    counted_cpp_delete,
    static_cast<void (*)(void*)>(&::operator delete),
    cpp_delete);
VECTORNET_DYLD_INTERPOSE(
    counted_cpp_delete_array,
    static_cast<void (*)(void*)>(&::operator delete[]),
    cpp_delete_array);

}  // namespace

extern "C" void vectornet_allocation_gate_begin() noexcept {
    for (auto& counter : counters) {
        counter.store(0, std::memory_order_relaxed);
    }
    gate_active.store(true, std::memory_order_release);
}

extern "C" void vectornet_allocation_gate_end(
    std::uint64_t* output,
    std::size_t output_count) noexcept {
    gate_active.store(false, std::memory_order_release);
    const std::size_t copy_count = output_count < counter_count
        ? output_count
        : counter_count;
    for (std::size_t index = 0; index < copy_count; ++index) {
        output[index] = counters[index].load(std::memory_order_relaxed);
    }
}

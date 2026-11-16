#pragma once
#include <cerrno>
#include <cstdint>
#include <system_error>
#include <time.h>

inline std::uint64_t monotonic_milliseconds() {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        throw std::system_error(errno, std::generic_category(), "clock_gettime");
    return static_cast<std::uint64_t>(value.tv_sec) * 1000 + value.tv_nsec / 1000000;
}

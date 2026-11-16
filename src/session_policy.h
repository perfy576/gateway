#pragma once
#include <algorithm>
#include <cmath>
#include <stdexcept>

constexpr long long DEFAULT_SERVICE_COOKIE_SECONDS = 43200;
constexpr long long BROWSER_COOKIE_LIMIT_SECONDS = 400LL * 86400;
constexpr double MAX_COOKIE_HOURS = 876000;

inline long long cookie_seconds_from_hours(double hours) {
    if (!std::isfinite(hours) || hours < 0 || hours > MAX_COOKIE_HOURS)
        throw std::invalid_argument("Invalid cookie lifetime");
    if (hours == 0) return 0;
    return std::max(1LL, static_cast<long long>(std::ceil(hours * 3600 - 1e-9)));
}
inline long long session_expires_at(long long created, long long lifetime) {
    return lifetime == 0 ? 0 : created + lifetime;
}
inline bool session_is_alive(long long expires, long long current_time) {
    return expires == 0 || expires > current_time;
}
inline bool session_is_online(long long last_seen, long long current_time) {
    return last_seen > current_time - 60;
}
inline long long browser_cookie_age(long long remaining) {
    return remaining == 0 ? BROWSER_COOKIE_LIMIT_SECONDS : std::min(remaining, BROWSER_COOKIE_LIMIT_SECONDS);
}

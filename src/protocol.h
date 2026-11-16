#pragma once
#include "security.h"
inline constexpr int TOKEN_VERSION=1;
inline constexpr int COOKIE_VERSION=1;
inline constexpr const char *BINDING_COOKIE="__Host-gateway_binding";
std::string cookie_value(const std::string& header, const std::string& name);
bool valid_cookie_v1(const std::string& value);
std::string verification_key(const std::string& signing_secret);
nlohmann::json verify_access_token(const std::string& token, const std::string& secret,
    const std::string& issuer, const std::string& audience, const std::string& cookies,
    const std::string& method, const std::string& uri);

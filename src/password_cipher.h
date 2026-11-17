#pragma once
#include <memory>
#include <string>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

class PasswordCipher {
    std::shared_ptr<EVP_PKEY> key_;
    nlohmann::json jwk_;
public:
    explicit PasswordCipher(const std::string& path);
    nlohmann::json public_key() const { return jwk_; }
    nlohmann::json decrypt(const std::string& envelope, const std::string& audience,
        const std::string& username, const nlohmann::json& context, long long now_ms) const;
};

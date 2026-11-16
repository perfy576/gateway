#pragma once
#include <string>
#include <unordered_map>
#include <nlohmann/json.hpp>
std::string random_hex(size_t bytes = 32);
std::string sha256(const std::string& value);
bool secure_equal(const std::string& a, const std::string& b);
std::string hmac_sha256_hex(const std::string& key, const std::string& value);
std::string password_hash(const std::string& password, const std::string& salt = "");
bool password_verify(const std::string& password, const std::string& encoded);
std::string encode_url(const std::string& value);
std::string decode_url(const std::string& value);
std::unordered_map<std::string,std::string> query_params(const std::string& uri);
bool valid_host(const std::string& host);
bool valid_path(const std::string& path);
struct Upstream { std::string scheme, address, hostname; };
Upstream parse_upstream(const std::string& value);
std::string base64url(const std::string& value);
std::string sign_jwt(const nlohmann::json& claims, const std::string& secret);
nlohmann::json verify_jwt(const std::string& token, const std::string& secret, const std::string& issuer, const std::string& audience);

#include "security.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <algorithm>
#include <cctype>
#include <regex>
#include <stdexcept>
#include <jwt-cpp/jwt.h>

static std::string hex(const unsigned char *data, size_t n) {
    const char *digits = "0123456789abcdef";
    std::string out; out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { out += digits[data[i] >> 4]; out += digits[data[i] & 15]; }
    return out;
}
std::string random_hex(size_t bytes) {
    std::string data(bytes, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char *>(data.data()), bytes) != 1) throw std::runtime_error("Random source failed");
    return hex(reinterpret_cast<const unsigned char *>(data.data()), bytes);
}
std::string sha256(const std::string& value) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(value.data()), value.size(), digest);
    return hex(digest, sizeof digest);
}
bool secure_equal(const std::string& a, const std::string& b) {
    return a.size()==b.size() && CRYPTO_memcmp(a.data(),b.data(),a.size())==0;
}
std::string hmac_sha256_hex(const std::string& key, const std::string& value) {
    unsigned char digest[EVP_MAX_MD_SIZE];unsigned length=0;
    if (!HMAC(EVP_sha256(),key.data(),key.size(),reinterpret_cast<const unsigned char *>(value.data()),value.size(),digest,&length))
        throw std::runtime_error("HMAC failed");
    return hex(digest,length);
}
std::string password_hash(const std::string& password, const std::string& salt) {
    std::string actual = salt.empty() ? random_hex(16) : salt;
    unsigned char key[32];
    if (EVP_PBE_scrypt(password.data(), password.size(), reinterpret_cast<const unsigned char *>(actual.data()), actual.size(),
        16384, 8, 1, 64 * 1024 * 1024, key, sizeof key) != 1) throw std::runtime_error("Password derivation failed");
    return "scrypt$" + actual + "$" + hex(key, sizeof key);
}
bool password_verify(const std::string& password, const std::string& encoded) {
    if (encoded.size() != 104 || encoded.substr(0, 7) != "scrypt$") return false;
    std::string computed = password_hash(password, encoded.substr(7, 32));
    return CRYPTO_memcmp(computed.data(), encoded.data(), encoded.size()) == 0;
}
std::string encode_url(const std::string& value) {
    const char *digits = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out += c;
        else { out += '%'; out += digits[c >> 4]; out += digits[c & 15]; }
    }
    return out;
}
std::string decode_url(const std::string& value) {
    std::string out;
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%' && i + 2 < value.size() && std::isxdigit(value[i+1]) && std::isxdigit(value[i+2])) {
            out += static_cast<char>(std::stoi(value.substr(i+1, 2), nullptr, 16)); i += 2;
        } else out += value[i] == '+' ? ' ' : value[i];
    }
    return out;
}
std::unordered_map<std::string,std::string> query_params(const std::string& uri) {
    std::unordered_map<std::string,std::string> result;
    auto pos = uri.find('?'); if (pos == std::string::npos) return result;
    size_t start = pos + 1;
    while (start < uri.size()) {
        auto end = uri.find('&', start); if (end == std::string::npos) end = uri.size();
        auto eq = uri.find('=', start);
        if (eq < end) result[decode_url(uri.substr(start, eq-start))] = decode_url(uri.substr(eq+1, end-eq-1));
        start = end + 1;
    }
    return result;
}
bool valid_host(const std::string& host) {
    static const std::regex pattern(R"(^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$)");
    return host.size() <= 253 && std::regex_match(host, pattern);
}
bool valid_path(const std::string& path) {
    if (path.empty() || path.size() > 4096 || path[0] != '/' || path.rfind("//", 0) == 0) return false;
    for (unsigned char c : path) if (c < 32 || c == 127 || c == '\\' || c == '#') return false;
    auto decoded = decode_url(path);
    if (decoded.rfind("//", 0) == 0) return false;
    for (unsigned char c : decoded) if (c < 32 || c == 127 || c == '\\') return false;
    return true;
}
Upstream parse_upstream(const std::string& value) {
    static const std::regex pattern(R"(^(http|https)://([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(:([0-9]{1,5}))?/?$)");
    std::smatch m;
    if (!std::regex_match(value, m, pattern)) throw std::invalid_argument("后端地址应为 http(s)://主机:端口，不包含路径");
    std::string host = m[2], port = m[4];
    if (!port.empty() && (std::stoi(port) < 1 || std::stoi(port) > 65535)) throw std::invalid_argument("后端端口无效");
    if (port.empty()) port = m[1] == "https" ? "443" : "80";
    std::string hostname = host;
    if (host.front() == '[') hostname = host.substr(1, host.size()-2);
    return {m[1], host + ":" + port, hostname};
}
std::string base64url(const std::string& value) {
    std::string output(4 * ((value.size() + 2) / 3), '\0');
    if (!value.empty()) EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output.data()),
        reinterpret_cast<const unsigned char *>(value.data()), value.size());
    while (!output.empty() && output.back() == '=') output.pop_back();
    std::replace(output.begin(), output.end(), '+', '-');
    std::replace(output.begin(), output.end(), '/', '_');
    return output;
}
static std::string jwt_prefix(int version) {
    nlohmann::json header={{"alg","HS256"},{"typ","JWT"},{"gwv",version}};
    return base64url(header.dump()) + ".";
}
std::string sign_jwt(const nlohmann::json& claims, const std::string& secret, std::string* encoded_payload) {
    static const std::string v1_prefix = jwt_prefix(1);
    const int version = claims.value("ver",1);
    auto payload = base64url(claims.dump());
    std::string input = version == 1 ? v1_prefix : jwt_prefix(version);
    input += payload;
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned length = 0;
    if (!HMAC(EVP_sha256(), secret.data(), secret.size(), reinterpret_cast<const unsigned char *>(input.data()),
          input.size(), digest, &length)) throw std::runtime_error("HMAC failed");
    input += ".";
    input += base64url(std::string(reinterpret_cast<char *>(digest), length));
    if (encoded_payload) *encoded_payload = std::move(payload);
    return input;
}
nlohmann::json verify_jwt(const std::string& token, const std::string& secret, const std::string& issuer, const std::string& audience) {
    if (token.empty() || token.size()>16384) throw std::invalid_argument("Invalid token size");
    auto decoded=jwt::decode(token);
    if (!decoded.has_expires_at() || !decoded.has_issued_at() || !decoded.has_id()) throw std::invalid_argument("Missing token claims");
    jwt::verify().allow_algorithm(jwt::algorithm::hs256(secret)).with_issuer(issuer).with_audience(audience).verify(decoded);
    auto claims=nlohmann::json::parse(decoded.get_payload()),head=nlohmann::json::parse(decoded.get_header());
    if (!claims.contains("ver") || !claims["ver"].is_number_integer() || claims["ver"]!=1 ||
        !head.contains("gwv") || !head["gwv"].is_number_integer() || head["gwv"]!=1)
        throw std::invalid_argument("Unsupported login request version");
    return claims;
}

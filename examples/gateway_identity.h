#pragma once
#include "protocol.h"

struct GatewayIdentity {
    bool authenticated;
    std::string user_id, username, display_name, role;
};

// Construct once per service; reuse this verifier across requests.
class GatewayVerifier {
    std::string secret_,issuer_,audience_;
public:
    GatewayVerifier(const std::string& secret, const std::string& issuer, const std::string& audience)
        : secret_(secret),issuer_(issuer),audience_(audience) {
        if (secret.size()!=64) throw std::invalid_argument("Expected the 64-character secret from Gateway");
    }
    GatewayIdentity verify(const std::string& token, const std::string& method, const std::string& original_uri,const std::string& cookie_header) const {
        auto claims=verify_access_token(token,secret_,issuer_,audience_,cookie_header,method,original_uri);
        return {claims["authenticated"],claims["sub"],claims["username"],claims["display_name"],claims["role"]};
    }
};

#include "protocol.h"
#include <jwt-cpp/jwt.h>
#include <algorithm>
#include <ctime>
#include <stdexcept>

std::string cookie_value(const std::string& source, const std::string& name) {
    std::string result;bool found=false;size_t pos=0;
    while (pos<source.size()) {
        size_t end=source.find(';',pos);if(end==std::string::npos)end=source.size();
        size_t start=source.find_first_not_of(" \t",pos);
        if(start<end && source.compare(start,name.size()+1,name+"=")==0) {
            if(found)throw std::invalid_argument("Duplicate gateway cookie");
            result=source.substr(start+name.size()+1,end-start-name.size()-1);found=true;
        }
        pos=end+1;
    }
    return result;
}
bool valid_cookie_v1(const std::string& value) {
    return value.size()==67 && value.rfind("v1.",0)==0 &&
        std::all_of(value.begin()+3,value.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');});
}
std::string verification_key(const std::string& secret) {
    return hmac_sha256_hex(secret,"gateway/verify-api/v1");
}
nlohmann::json verify_access_token(const std::string& token, const std::string& secret,
    const std::string& issuer, const std::string& audience, const std::string& cookies,
    const std::string& method, const std::string& uri) {
    if(token.empty() || token.size()>16384 || cookies.size()>32768 || method.empty() || method.size()>32 || !valid_path(uri))
        throw std::invalid_argument("Invalid verification input");
    auto decoded=jwt::decode(token);
    auto claims=nlohmann::json::parse(decoded.get_payload()),head=nlohmann::json::parse(decoded.get_header());
    for(const auto *key:{"ver","cookie_version","iat","nbf","exp"})
        if(!claims.contains(key)||!claims[key].is_number_integer())throw std::invalid_argument("Missing integer claim");
    if(claims["ver"]!=TOKEN_VERSION || claims["cookie_version"]!=COOKIE_VERSION || !head.contains("gwv") ||
        !head["gwv"].is_number_integer() || head["gwv"]!=TOKEN_VERSION || head.value("typ",std::string())!="JWT")
        throw std::invalid_argument("Unsupported token or cookie version");
    for(const auto *key:{"iss","aud","sub","sid","username","display_name","role","type","cookie_name","cookie_sha256","request_method","request_uri_sha256"})
        if(!claims.contains(key)||!claims[key].is_string())throw std::invalid_argument("Missing string claim");
    if(!claims.contains("authenticated")||!claims["authenticated"].is_boolean())throw std::invalid_argument("Missing authentication claim");
    auto iat=claims["iat"].get<long long>(),exp=claims["exp"].get<long long>(),nbf=claims["nbf"].get<long long>(),t=static_cast<long long>(std::time(nullptr));
    if(iat>t+3 || iat<t-63 || exp<=t-3 || exp>t+63 || nbf>t+3 || nbf<t-66 || exp<=iat || exp-iat>60 || claims["type"]!="gateway_access" || claims["cookie_name"]!=BINDING_COOKIE)
        throw std::invalid_argument("Invalid token scope or lifetime");
    jwt::verify().allow_algorithm(jwt::algorithm::hs256(secret)).with_issuer(issuer).with_audience(audience).leeway(3).verify(decoded);
    auto binding=cookie_value(cookies,BINDING_COOKIE);
    if(!valid_cookie_v1(binding) || !secure_equal(claims["cookie_sha256"],sha256(binding)))throw std::invalid_argument("Gateway cookie mismatch");
    if(claims["request_method"]!=method || !secure_equal(claims["request_uri_sha256"],sha256(uri)))throw std::invalid_argument("Request mismatch");
    const bool authenticated=claims["authenticated"];
    if(authenticated ? (claims["sub"].get<std::string>().empty() || claims["sid"].get<std::string>().size()!=64) :
        (!claims["sub"].get<std::string>().empty() || !claims["sid"].get<std::string>().empty() || !claims["username"].get<std::string>().empty() ||
         !claims["display_name"].get<std::string>().empty() || !claims["role"].get<std::string>().empty()))throw std::invalid_argument("Invalid session claims");
    return claims;
}

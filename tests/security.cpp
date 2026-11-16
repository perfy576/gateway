#include "security.h"
#include "gateway_identity.h"
#include <functional>
#include <iostream>

static void require(bool value,const char *message) { if (!value) throw std::runtime_error(message); }
static void rejects(const std::function<void()>& action) {
    bool rejected=false; try { action(); } catch (...) { rejected=true; }
    require(rejected,"Expected rejection");
}
int main() {
    auto secret=random_hex(); auto t=std::time(nullptr);
    auto binding="v1."+random_hex(),cookies=std::string(BINDING_COOKIE)+"="+binding;
    GatewayVerifier verifier(secret,"https://gateway.example.com","app.example.com");
    nlohmann::json claims={{"iss","https://gateway.example.com"},{"aud","app.example.com"},{"sub","1"},
        {"iat",t},{"nbf",t-2},{"exp",t+60},{"authenticated",true},{"username","admin"},{"display_name","Test"},{"role","admin"},
        {"request_method","GET"},{"request_uri_sha256",sha256("/private?x=1")},
        {"ver",1},{"type","gateway_access"},{"cookie_version",1},{"cookie_name",BINDING_COOKIE},{"cookie_sha256",sha256(binding)},{"sid",random_hex()}};
    auto verify=[&](const std::string& token){return verifier.verify(token,"GET","/private?x=1",cookies);};
    auto token=sign_jwt(claims,secret); auto identity=verify(token);
    require(identity.authenticated && identity.user_id=="1" && identity.username=="admin","JWT interoperability");
    rejects([&]{verify(sign_jwt(claims,random_hex()));});
    auto modified=claims; modified["aud"]="wrong.example.com"; rejects([&]{verify(sign_jwt(modified,secret));});
    modified=claims; modified["iss"]="https://attacker.invalid"; rejects([&]{verify(sign_jwt(modified,secret));});
    modified=claims; modified["exp"]=t-10; rejects([&]{verify(sign_jwt(modified,secret));});
    modified=claims; modified["nbf"]=t+20; rejects([&]{verify(sign_jwt(modified,secret));});
    modified=claims; modified["iat"]=t+20; modified["exp"]=t+80; rejects([&]{verify(sign_jwt(modified,secret));});
    modified=claims; modified.erase("exp"); rejects([&]{verify(sign_jwt(modified,secret));});
    modified=claims; modified["exp"]=t+3600; rejects([&]{verify(sign_jwt(modified,secret));});
    rejects([&]{verify("eyJhbGciOiJub25lIn0."+base64url(claims.dump())+".");});
    rejects([&]{verifier.verify(token,"POST","/private?x=1",cookies);});
    rejects([&]{verifier.verify(token,"GET","/other-path",cookies);});
    rejects([&]{verifier.verify(token,"GET","/private?x=1","");});
    rejects([&]{verifier.verify(token,"GET","/private?x=1",cookies+"; "+cookies);});
    modified=claims;modified["ver"]=2;rejects([&]{verify(sign_jwt(modified,secret));});
    modified=claims;modified["cookie_version"]=2;rejects([&]{verify(sign_jwt(modified,secret));});
    modified=claims;modified["cookie_sha256"]=sha256("different");rejects([&]{verify(sign_jwt(modified,secret));});
    modified=claims; modified["authenticated"]=false; modified["sub"]="";modified["sid"]="";modified["username"]="";modified["display_name"]="";modified["role"]="";
    require(!verify(sign_jwt(modified,secret)).authenticated,"Anonymous identity");
    auto hash=password_hash("correct-horse-example");
    require(password_verify("correct-horse-example",hash),"Password round trip");
    require(!password_verify("incorrect",hash),"Wrong password");
    require(password_hash("correct-horse-example")!=hash,"Unique salts");
    require(!valid_path("//evil.invalid") && !valid_path("/%2fevil.invalid") && !valid_path("/\\evil.invalid"),"Redirect safety");
    require(valid_path("/original?x=1&y=2"),"Return URL");
    require(parse_upstream("https://remote.example.com:8443").hostname=="remote.example.com","Remote upstream");
    rejects([]{parse_upstream("http://user:password@host/path");});
    std::cout<<"Security checks passed: jwt-cpp interoperability, signature, issuer, audience, expiry, nbf, iat, missing claims, lifetime, algorithm confusion, anonymous identity, scrypt and redirect validation.\n";
}

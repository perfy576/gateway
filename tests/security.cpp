#include "security.h"
#include "password_cipher.h"
#include "gateway_identity.h"
#include "session_policy.h"
#include <functional>
#include <iostream>
#include <limits>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>

static void require(bool value,const char *message) { if (!value) throw std::runtime_error(message); }
static void rejects(const std::function<void()>& action) {
    bool rejected=false; try { action(); } catch (...) { rejected=true; }
    require(rejected,"Expected rejection");
}
int main() {
    require(cookie_seconds_from_hours(0)==0,"Unlimited cookie lifetime");
    require(cookie_seconds_from_hours(0.5)==1800,"Fractional cookie hours");
    require(cookie_seconds_from_hours(1.25)==4500,"Cookie hour precision");
    require(cookie_seconds_from_hours(0.000001)==1,"Positive cookie lifetime must not become unlimited");
    rejects([]{cookie_seconds_from_hours(-1);});
    rejects([]{cookie_seconds_from_hours(std::numeric_limits<double>::infinity());});
    rejects([]{cookie_seconds_from_hours(std::numeric_limits<double>::quiet_NaN());});
    rejects([]{cookie_seconds_from_hours(MAX_COOKIE_HOURS+1);});
    require(session_expires_at(100,0)==0 && session_is_alive(0,9999999999LL),"Unlimited session expiry");
    require(session_is_alive(120,119) && !session_is_alive(120,120) && !session_is_alive(-1,120),"Exact session expiry");
    require(browser_cookie_age(0)==BROWSER_COOKIE_LIMIT_SECONDS && browser_cookie_age(1800)==1800,"Browser cookie limit");
    require(session_is_online(100,159) && !session_is_online(100,160),"Online session one-minute boundary");
    require(session_is_alive(1000,160) && !session_is_online(100,160),"Valid sessions can be offline");
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
    char key_dir[]="/tmp/gateway-password-key-XXXXXX";
    require(mkdtemp(key_dir)!=nullptr,"Create password key test directory");
    struct Cleanup {std::string path;~Cleanup(){std::filesystem::remove_all(path);}} cleanup{key_dir};
    const auto key_path=std::string(key_dir)+"/private.pem";
    PasswordCipher cipher(key_path),restored(key_path);
    require(cipher.public_key()==restored.public_key(),"Persistent password encryption key");
    require(!cipher.public_key().contains("d")&&cipher.public_key().at("alg")=="RSA-OAEP-256","Public encryption key only");
    struct stat key_stat{};require(stat(key_path.c_str(),&key_stat)==0&&(key_stat.st_mode&0777)==0600,"Private key permissions");
    const auto link=std::string(key_dir)+"/link.pem";
    require(symlink(key_path.c_str(),link.c_str())==0,"Create key symlink test");
    rejects([&]{PasswordCipher unsafe(link);});
    require(chmod(key_path.c_str(),0644)==0,"Set unsafe key permissions");
    rejects([&]{PasswordCipher unsafe(key_path);});
    require(chmod(key_path.c_str(),0600)==0,"Restore key permissions");
    require(!valid_path("//evil.invalid") && !valid_path("/%2fevil.invalid") && !valid_path("/\\evil.invalid"),"Redirect safety");
    require(valid_path("/original?x=1&y=2"),"Return URL");
    require(parse_upstream("https://remote.example.com:8443").hostname=="remote.example.com","Remote upstream");
    rejects([]{parse_upstream("http://user:password@host/path");});
    std::cout<<"Security checks passed: jwt-cpp interoperability, signature, issuer, audience, expiry, nbf, iat, missing claims, lifetime, algorithm confusion, anonymous identity, scrypt and redirect validation.\n";
}

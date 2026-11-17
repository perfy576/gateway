#include "db.h"
#include "security.h"
#include "protocol.h"
#include "session_policy.h"
#include <workflow/WFHttpServer.h>
#include <workflow/WFTaskFactory.h>
#include <workflow/HttpUtil.h>
#include <workflow/WFGlobal.h>
#include <jwt-cpp/jwt.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <thread>
#include <unordered_set>
#include <fcntl.h>
#include <unistd.h>

using json = nlohmann::json;
static long long now() { return std::time(nullptr); }
struct HttpError : std::runtime_error {
    int status;
    HttpError(int code, const std::string& message) : std::runtime_error(message), status(code) {}
};
struct User {
    std::string id, username, name, hash, role;
    bool enabled;
};
static json user_json(const User& u) {
    return {{"id",u.id},{"username",u.username},{"display_name",u.name},{"role",u.role},{"enabled",u.enabled}};
}
struct Service {
    std::string id, name, host, upstream, secret, appid;
    Upstream target;
    bool enabled, allow_all;
    std::vector<std::string> excluded, users;
    long long cookie_lifetime = DEFAULT_SERVICE_COOKIE_SECONDS;
    bool builtin = false;
};
static json service_json(const Service& s) {
    return {{"id",s.id},{"appid",s.appid},{"name",s.name},{"host",s.host},{"upstream",s.upstream},
        {"enabled",s.enabled},{"allow_all",s.allow_all},{"excluded_paths",s.excluded},{"users",s.users},
        {"cookie_max_age_hours",s.cookie_lifetime / 3600.0},{"builtin",s.builtin}};
}
struct Config {
    std::unordered_map<std::string,User> users;
    std::unordered_map<std::string,std::string> usernames;
    std::unordered_map<std::string,Service> services;
    std::unordered_map<std::string,std::string> hosts;
    std::unordered_map<std::string,std::string> appids;
};
static std::shared_ptr<const Config> config;
static std::mutex control_mutex;
static std::string public_host, origin, web_root, state_dir;
static long long session_lifetime;
static std::unordered_map<std::string,std::pair<std::string,std::string>> assets;
static std::atomic<unsigned> pending{0};
static std::atomic<unsigned long long> auth_requests{0}, auth_granted{0}, auth_rejected{0};
static const long long started = now();

struct ClientProtocol {
    std::string sdk_version="gateway";
    int token_version=TOKEN_VERSION,cookie_version=COOKIE_VERSION;
    bool online_only=false;
};
struct ClientInfo {
    std::string user_agent, app_package;
};
struct Session {
    std::string user_id, ip, host, binding_hash;
    long long expires, created;
    ClientProtocol protocol;
    std::string service_id;
    long long cookie_lifetime, cookie_refreshed, last_seen;
    ClientInfo client;
};
static std::unordered_map<std::string,Session> sessions;
static std::shared_mutex session_mutex;
struct Flow {
    std::string verifier_hash, service_id, path, ticket_hash, user_id, request_hash, host;
    long long expires, ticket_expires = 0;
    ClientProtocol protocol;
};
static std::unordered_map<std::string,Flow> flows;
static std::unordered_map<std::string,long long> used_login_tokens;
static std::mutex flow_mutex;
struct Bucket { long long start; unsigned count; };
static std::unordered_map<std::string,Bucket> buckets;
static std::mutex bucket_mutex;

static std::shared_ptr<const Config> snapshot() { return std::atomic_load(&config); }
static void load_config() {
    auto next = std::make_shared<Config>();
    for (const auto& r : db().query("SELECT id,username,display_name,password_hash,role,enabled FROM users")) {
        User u{r[0],r[1],r[2],r[3],r[4],r[5]=="1"};
        next->usernames[u.username] = u.id; next->users[u.id] = u;
    }
    for (const auto& r : db().query("SELECT id,name,host,upstream,token_secret,enabled,allow_all,excluded_paths,appid,cookie_max_age_seconds FROM services")) {
        Service s{r[0],r[1],r[2],r[3],r[4],r[8],parse_upstream(r[3]),r[5]=="1",r[6]=="1",json::parse(r[7]).get<std::vector<std::string>>(),{}};
        s.cookie_lifetime=std::stoll(r[9]);
        s.builtin=s.host==public_host;
        next->hosts[s.host] = s.id; next->appids[s.appid]=s.id; next->services[s.id] = std::move(s);
    }
    for (const auto& r : db().query("SELECT service_id,user_id FROM service_users")) {
        auto found = next->services.find(r[0]);
        if (found != next->services.end()) found->second.users.push_back(r[1]);
    }
    auto console=next->hosts.find(public_host);
    if(console==next->hosts.end())throw std::runtime_error("Built-in console service is missing");
    auto& console_users=next->services.at(console->second).users;
    for(const auto& [id,user]:next->users)
        if(user.role=="admin" && std::find(console_users.begin(),console_users.end(),id)==console_users.end())console_users.push_back(id);
    std::atomic_store(&config, std::shared_ptr<const Config>(next));
}
static const Service& console_service(const Config& c) {
    return c.services.at(c.hosts.at(public_host));
}
static std::string header(WFHttpTask *task, const std::string& name) {
    protocol::HttpHeaderCursor cursor(task->get_req()); std::string value;
    cursor.find(name, value); return value;
}
static ClientInfo client_info(WFHttpTask *task) {
    auto agent=header(task,"User-Agent").substr(0,1024);
    for(auto& c:agent)if(static_cast<unsigned char>(c)<32 || c==127)c=' ';
    // Keep arbitrary header bytes valid UTF-8 for both JSON and MySQL.
    agent=json::parse(json(agent).dump(-1,' ',false,json::error_handler_t::replace)).get<std::string>();
    auto package=header(task,"X-Gateway-App-Package");
    static const std::regex package_pattern(R"(^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$)");
    if(!std::regex_match(package,package_pattern))package.clear();
    return {agent,package};
}
static std::string cookie(WFHttpTask *task, const std::string& name) {
    try { return cookie_value(header(task,"Cookie"),name); }
    catch (const std::invalid_argument&) { return ""; }
}
static std::string clean_cookies(WFHttpTask *task, const std::string& binding) {
    std::string source = header(task,"Cookie"), output;
    size_t pos = 0;
    while (pos < source.size()) {
        size_t end = source.find(';',pos); if (end == std::string::npos) end=source.size();
        size_t start=source.find_first_not_of(" \t",pos);
        const std::string gateway_prefix="__Host-gateway_";
        if (start < end && source.compare(start,gateway_prefix.size(),gateway_prefix) != 0) {
            if (!output.empty()) output += "; ";
            output += source.substr(start,end-start);
        }
        pos=end+1;
    }
    if(!output.empty())output+="; ";
    return output+BINDING_COOKIE+"="+binding;
}
static std::string cookie_header_value(const std::string& name,const std::string& value,long long lifetime) {
    auto age=value.empty()?0:browser_cookie_age(lifetime);
    return name+"="+value+"; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age="+std::to_string(age);
}
static void set_cookie(WFHttpTask *task, const std::string& name, const std::string& value, long long lifetime) {
    task->get_resp()->add_header_pair("Set-Cookie",cookie_header_value(name,value,lifetime));
}
static std::string ip(WFHttpTask *task) {
    auto value = header(task,"X-Forwarded-For"); auto comma=value.find(',');
    if (comma != std::string::npos) value=value.substr(0,comma);
    return value.substr(0,64);
}
static void respond(WFHttpTask *task, int status, const json& value) {
    task->get_resp()->set_status_code(std::to_string(status));
    task->get_resp()->set_header_pair("Content-Type","application/json; charset=utf-8");
    task->get_resp()->append_output_body(value.dump());
}
static void redirect(WFHttpTask *task, const std::string& location) {
    task->get_resp()->set_status_code("302"); task->get_resp()->set_header_pair("Location",location);
}
static void rate_limit(const std::string& key, unsigned limit, long long seconds = 60) {
    std::lock_guard lock(bucket_mutex);
    auto t=now();
    if (buckets.size()>20000) {
        for (auto it=buckets.begin();it!=buckets.end();) {
            if (it->second.start+300<t) it=buckets.erase(it); else ++it;
        }
        if (buckets.size()>20000) throw HttpError(429,"请求过于频繁，请稍后重试");
    }
    auto& b=buckets[key];
    if (b.start+seconds<=t) b={t,0};
    if (++b.count>limit) throw HttpError(429,"请求过于频繁，请稍后重试");
}
static const Service& service_by_host(const Config& c, const std::string& host) {
    auto it=c.hosts.find(host);
    if (it==c.hosts.end()) throw HttpError(404,"该域名未接入网关");
    const auto& s=c.services.at(it->second);
    if(s.builtin)throw HttpError(400,"内置控制台不提供业务反向代理");
    if (!s.enabled) throw HttpError(403,"该服务已停用");
    return s;
}
static const Service& service_by_appid(const Config& c,const std::string& appid) {
    auto found=c.appids.find(appid);
    if(found==c.appids.end()||!c.services.at(found->second).enabled||c.services.at(found->second).builtin)throw HttpError(400,"AppID 无效或服务已停用");
    return c.services.at(found->second);
}
static void disabled_service_headers(WFHttpTask *task,const Service& service) {
    task->get_resp()->set_header_pair("X-Gateway-Redirect-Reason","service_disabled");
    task->get_resp()->set_header_pair("X-Gateway-Service-Appid",service.appid);
}
static bool redirect_disabled_service(WFHttpTask *task,const Config& c,const std::string& host,const std::string& method,bool nginx=false) {
    auto found=c.hosts.find(host);
    if(found==c.hosts.end())return false;
    const auto& service=c.services.at(found->second);
    if(service.builtin||service.enabled)return false;
    const auto target=origin+"/?reason=service_disabled&appid="+encode_url(service.appid);
    disabled_service_headers(task,service);
    task->get_resp()->set_header_pair("X-Gateway-Redirect",target);
    if(!nginx&&(method=="GET"||method=="HEAD"))redirect(task,target);
    else respond(task,403,{{"error","该服务已停用"},{"reason","service_disabled"},{"redirect_url",target}});
    return true;
}
static bool permitted(const Service& s, const User& u) {
    return u.enabled && ((s.builtin && u.role=="admin") || s.allow_all || std::find(s.users.begin(),s.users.end(),u.id)!=s.users.end());
}
static std::string session_key(WFHttpTask *task) {
    auto token=cookie(task,"__Host-gateway_session");
    return valid_cookie_v1(token) ? sha256(token) : "";
}
static long long session_expiry(const Session& session, const Config& c) {
    if (session.service_id.empty()) return session.host==public_host ? session.expires : -1;
    auto service=c.services.find(session.service_id);
    if(service==c.services.end() || !service->second.enabled || service->second.host!=session.host) return -1;
    return session_expires_at(session.created,service->second.cookie_lifetime);
}
static User current_user(WFHttpTask *task, const Config& c, bool required=true) {
    std::string id, service_id, key=session_key(task),binding=cookie(task,BINDING_COOKIE);
    auto t=now();bool touch=false;
    {
        std::shared_lock lock(session_mutex); auto it=sessions.find(key);
        if (it!=sessions.end() && session_is_alive(session_expiry(it->second,c),now()) && it->second.host==header(task,"Host") &&
            valid_cookie_v1(binding) && secure_equal(it->second.binding_hash,sha256(binding)) &&
            (it->second.service_id.empty() || (c.hosts.count(it->second.host) && c.hosts.at(it->second.host)==it->second.service_id))) {
            id=it->second.user_id;service_id=it->second.service_id;touch=it->second.last_seen<t;
        }
    }
    auto found=c.users.find(id);
    auto service=c.services.find(service_id);
    if (found!=c.users.end() && service!=c.services.end() && permitted(service->second,found->second)) {
        bool refresh=false;long long remaining=0;
        if(service->second.builtin){
            std::shared_lock lock(session_mutex);auto it=sessions.find(key);
            if(it!=sessions.end()){
                refresh=it->second.cookie_lifetime!=service->second.cookie_lifetime||t-it->second.cookie_refreshed>=86400;
                auto expiry=session_expiry(it->second,c);remaining=expiry==0?0:std::max(1LL,expiry-t);
            }
        }
        if(touch||refresh){
            std::unique_lock lock(session_mutex);auto it=sessions.find(key);
            if(it!=sessions.end()){
                it->second.last_seen=std::max(t,it->second.last_seen);
                if(refresh){it->second.cookie_refreshed=t;it->second.cookie_lifetime=service->second.cookie_lifetime;}
            }
        }
        if(refresh){set_cookie(task,"__Host-gateway_session",cookie(task,"__Host-gateway_session"),remaining);set_cookie(task,BINDING_COOKIE,binding,remaining);}
        return found->second;
    }
    if (required) throw HttpError(401,"请先登录");
    return {"","","","","",false};
}
static void revoke_user(const std::string& id) {
    {
        std::unique_lock lock(session_mutex);
        for (auto it=sessions.begin();it!=sessions.end();) {
            if (it->second.user_id==id) it=sessions.erase(it); else ++it;
        }
    }
    std::lock_guard lock(flow_mutex);
    for (auto it=flows.begin();it!=flows.end();) {
        if (it->second.user_id==id) it=flows.erase(it); else ++it;
    }
}
struct IssuedSession { std::string token, binding; long long lifetime; };
static IssuedSession issue_session(WFHttpTask *task,const User& user,const std::string& host,
    const ClientProtocol& protocol,const std::string& service_id,bool replace_browser_session) {
    std::string token="v1."+random_hex(),binding="v1."+random_hex();
    std::unique_lock lock(session_mutex);
    auto live=snapshot();auto current=live->users.find(user.id);
    if (current==live->users.end() || !current->second.enabled || current->second.hash!=user.hash)
        throw HttpError(401,"账号状态已变更，请重新登录");
    long long lifetime=session_lifetime;
    const auto scope=service_id.empty()?console_service(*live).id:service_id;
    {
        auto service=live->services.find(scope);
        if(service==live->services.end()||!service->second.enabled||service->second.host!=host||!permitted(service->second,current->second))
            throw HttpError(403,"服务已停用或无访问权限");
        lifetime=service->second.cookie_lifetime;
    }
    if (sessions.size()>=100000) throw HttpError(503,"会话数量已达上限");
    if(replace_browser_session){auto old=session_key(task);if(!old.empty())sessions.erase(old);}
    auto t=now();
    sessions[sha256(token)]={user.id,ip(task),host,sha256(binding),session_expires_at(t,lifetime),t,protocol,scope,lifetime,t,t,client_info(task)};
    return {token,binding,lifetime};
}
static void new_session(WFHttpTask *task, const User& user,const ClientProtocol& protocol={},const std::string& service_id={}) {
    auto [token,binding,lifetime]=issue_session(task,user,header(task,"Host"),protocol,service_id,true);
    set_cookie(task,"__Host-gateway_session",token,lifetime);
    set_cookie(task,BINDING_COOKIE,binding,lifetime);
}
static void csrf(WFHttpTask *task, bool authenticated) {
    if (header(task,"Origin")!=origin) throw HttpError(403,"请求来源校验失败");
    if (header(task,"Content-Type").rfind("application/json",0)!=0 || header(task,"X-Gateway-Request")!="1")
        throw HttpError(403,"请求格式校验失败");
    if (authenticated && header(task,"X-CSRF-Token")!=sha256("csrf:"+cookie(task,"__Host-gateway_session")))
        throw HttpError(403,"会话校验失败，请刷新页面");
}
static json body(WFHttpTask *task) {
    auto data=protocol::HttpUtil::decode_chunked_body(task->get_req());
    auto value=json::parse(data,nullptr,false);
    if (!value.is_object()) throw HttpError(400,"请求 JSON 无效");
    return value;
}
static std::string text_field(const json& b, const char *key, size_t minimum, size_t maximum) {
    if (!b.contains(key) || !b[key].is_string()) throw HttpError(400,std::string("缺少字段: ")+key);
    auto value=b[key].get<std::string>();
    if (value.size()<minimum || value.size()>maximum) throw HttpError(400,std::string("字段长度无效: ")+key);
    for (unsigned char c:value) if (c<32 || c==127) throw HttpError(400,"字段包含控制字符");
    return value;
}
static void audit(WFHttpTask *task, const std::string& actor, const std::string& action, const std::string& detail) {
    auto client=client_info(task);
    db().query("INSERT INTO audit_logs(actor,action,detail,ip,user_agent,app_package) VALUES(?,?,?,?,?,?)",
        {actor,action,detail.substr(0,2048),ip(task),client.user_agent,client.app_package});
}
static bool excluded_path(const Service& service, const std::string& uri) {
    auto path=uri.substr(0,uri.find('?'));
    // Ambiguous encodings and dot segments never qualify for an authentication exemption.
    if (!valid_path(path) || path.find('%')!=std::string::npos || path.find("//")!=std::string::npos ||
        path.find("/./")!=std::string::npos || path.find("/../")!=std::string::npos ||
        (path.size()>=2 && path.substr(path.size()-2)=="/.") ||
        (path.size()>=3 && path.substr(path.size()-3)=="/..")) return false;
    for (const auto& rule:service.excluded) {
        if (rule.size()>=2 && rule.substr(rule.size()-2)=="/*") {
            if (path.rfind(rule.substr(0,rule.size()-1),0)==0) return true;
        } else if (path==rule) return true;
    }
    return false;
}
static std::string make_login_request(WFHttpTask *task, const Service& service, const std::string& path,const ClientProtocol& protocol={}) {
    if (!valid_path(path) || path.rfind("/_gateway/",0)==0) throw HttpError(400,"返回地址无效");
    rate_limit("flow:"+ip(task),60);
    std::string id=random_hex(),verifier="v1."+random_hex(); auto expiry=now()+300;
    json claims={{"iss",origin},{"aud",origin+"/login"},{"jti",id},{"iat",now()},{"exp",expiry},
        {"service_id",service.id},{"appid",service.appid},{"return_url","https://"+service.host+path},{"ver",TOKEN_VERSION},{"type","login_request"},
        {"sdk_version",protocol.sdk_version},{"token_version",protocol.token_version},{"cookie_version",protocol.cookie_version},{"online_only",protocol.online_only}};
    auto token=sign_jwt(claims,hmac_sha256_hex(service.secret,"gateway/browser-login/v1"));
    {
        std::lock_guard lock(flow_mutex);
        if (flows.size()>=20000) throw HttpError(503,"登录请求过多，请稍后重试");
        flows[id]={sha256(verifier),service.id,path,"","",sha256(token),service.host,expiry,0,protocol};
    }
    set_cookie(task,"__Host-gateway_flow_"+id.substr(0,16),verifier,300);
    return origin+"/login?appid="+service.appid+"&token="+encode_url(token);
}
static std::pair<std::string,Flow> checked_flow(const std::string& token) {
    try {
        if(token.empty()||token.size()>16384)throw std::invalid_argument("Invalid token size");
        auto unverified=jwt::decode(token);auto payload=json::parse(unverified.get_payload());
        auto c=snapshot();const auto appid=payload.at("appid").get<std::string>();
        const auto& service=service_by_appid(*c,appid);
        auto claims=verify_jwt(token,hmac_sha256_hex(service.secret,"gateway/browser-login/v1"),origin,origin+"/login");
        if(claims.value("type",std::string())!="login_request")throw std::invalid_argument("Wrong token purpose");
        auto id=claims.at("jti").get<std::string>();
        std::lock_guard lock(flow_mutex);auto it=flows.find(id);
        if (it==flows.end() || it->second.expires<=now() || it->second.request_hash!=sha256(token))
            throw std::invalid_argument("Login request missing or expired");
        if (service.id!=it->second.service_id || !service.enabled || service.host!=it->second.host || claims.at("appid")!=service.appid)
            throw std::invalid_argument("Login service changed");
        return {id,it->second};
    } catch (const std::exception&) { throw HttpError(410,"登录请求无效或已过期"); }
}
struct SdkLogin {std::string service_id,path;ClientProtocol protocol;};
static SdkLogin validate_sdk_login(const Config& c,const std::string& token,const std::string& appid) {
    try {
        if(token.empty()||token.size()>16384)throw std::invalid_argument("Invalid request size");
        const auto& service=service_by_appid(c,appid);
        auto claims=verify_jwt(token,hmac_sha256_hex(service.secret,"gateway/sdk-login/v1"),service.host,origin+"/login");
        if(claims.at("appid")!=appid)throw std::invalid_argument("AppID mismatch");
        {std::lock_guard lock(flow_mutex);auto used=used_login_tokens.find(sha256(token));
         if(used!=used_login_tokens.end()&&used->second>now())throw HttpError(410,"登录 Token 已使用");}
        for(const auto *key:{"iat","nbf","exp"})if(!claims.contains(key)||!claims[key].is_number_integer())throw std::invalid_argument("Invalid timestamp");
        auto iat=claims["iat"].get<long long>(),exp=claims["exp"].get<long long>(),nbf=claims["nbf"].get<long long>(),t=now();
        if(iat<t-300||iat>t+3||exp<=t||exp>t+303||exp<=iat||exp-iat>300||nbf>t+3||nbf<t-303||claims.value("type",std::string())!="sdk_login")throw std::invalid_argument("Invalid login request lifetime or purpose");
        auto sdk=claims.at("sdk_version").get<std::string>();
        static const std::regex sdk_pattern(R"(^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$)");
        if(!std::regex_match(sdk,sdk_pattern)||!claims.contains("allow_verify")||!claims["allow_verify"].is_boolean())throw std::invalid_argument("Invalid SDK capabilities");
        auto supports=[&](const char *key,int current){
            const auto& versions=claims.at(key);if(!versions.is_array()||versions.empty()||versions.size()>32)throw std::invalid_argument("Invalid protocol list");
            bool found=false;for(const auto& version:versions){if(!version.is_number_integer()||version<1||version>1000000)throw std::invalid_argument("Invalid protocol version");if(version==current)found=true;}return found;
        };
        bool compatible_token=supports("token_versions",TOKEN_VERSION),compatible_cookie=supports("cookie_versions",COOKIE_VERSION);
        bool fallback=claims["allow_verify"].get<bool>();
        if((!compatible_token||!compatible_cookie)&&!fallback)throw HttpError(426,"SDK 与网关没有兼容的协议版本，请升级 SDK 或启用在线校验");
        auto url=claims.at("return_url").get<std::string>(),prefix="https://"+service.host;
        if(url.rfind(prefix+"/",0)!=0)throw std::invalid_argument("Return URL outside configured service");
        auto path=url.substr(prefix.size());if(!valid_path(path)||path.rfind("/_gateway/",0)==0)throw std::invalid_argument("Invalid return path");
        return {service.id,path,{sdk,TOKEN_VERSION,COOKIE_VERSION,!compatible_token||!compatible_cookie}};
    }catch(const HttpError& e){if(e.status==426||e.status==410)throw;throw HttpError(400,"SDK 登录请求无效或已过期");}
     catch(const std::exception&){throw HttpError(400,"SDK 登录请求无效或已过期");}
}
static void sdk_start(WFHttpTask *task,const Config& c,const std::string& token,const std::string& appid,bool business_host) {
    auto login=validate_sdk_login(c,token,appid);const auto& service=c.services.at(login.service_id);
    if(business_host){
        if(header(task,"Host")!=service.host)throw HttpError(400,"SDK 登录请求与当前域名不匹配");
        redirect(task,make_login_request(task,service,login.path,login.protocol));
    }else redirect(task,"https://"+service.host+"/_gateway/start?appid="+appid+"&token="+encode_url(token));
}
static User password_user(WFHttpTask *task,const Config& c,const std::string& name,const std::string& pass) {
    rate_limit("login-global",120);rate_limit("login-ip:"+ip(task),15);rate_limit("login-user:"+name,10);
    auto it=c.usernames.find(name);
    static const std::string dummy=password_hash(random_hex());
    const User *user=it==c.usernames.end()?nullptr:&c.users.at(it->second);
    bool valid=password_verify(pass,user?user->hash:dummy);
    if(!valid||!user||!user->enabled){audit(task,name,"login.failed","");throw HttpError(401,"用户名或密码错误");}
    return *user;
}
struct AppLoginRequest {SdkLogin login;std::string flow_id;long long expires;};
static AppLoginRequest checked_app_login(const Config& c,const std::string& appid,const std::string& token) {
    try{
        auto decoded=jwt::decode(token);auto claims=json::parse(decoded.get_payload());
        if(claims.value("type",std::string())=="sdk_login"){
            auto login=validate_sdk_login(c,token,appid);
            return {login,"",claims.at("exp").get<long long>()};
        }
        auto [id,flow]=checked_flow(token);const auto& service=service_by_appid(c,appid);
        if(service.id!=flow.service_id||claims.at("appid")!=appid)throw HttpError(400,"AppID 与登录 Token 不匹配");
        return {{service.id,flow.path,flow.protocol},id,flow.expires};
    }catch(const HttpError&){throw;}catch(const std::exception&){throw HttpError(400,"登录 Token 无效");}
}
static void app_login(WFHttpTask *task,const Config& c,const std::string& query_appid,const std::string& query_token) {
    rate_limit("app-login:"+ip(task),60);
    if(header(task,"Content-Type").rfind("application/json",0)!=0)throw HttpError(415,"请使用 application/json");
    auto b=body(task);
    for(const auto& [key,value]:std::vector<std::pair<std::string,std::string>>{{"appid",query_appid},{"token",query_token}}){
        if(value.empty())continue;
        if(b.contains(key)&&b[key]!=value)throw HttpError(400,"URL 与请求正文的登录参数不一致");
        b[key]=value;
    }
    auto appid=text_field(b,"appid",1,64),token=text_field(b,"token",1,16384);
    auto name=text_field(b,"username",1,64),pass=text_field(b,"passwd",1,256);
    checked_app_login(c,appid,token);
    auto user=password_user(task,c,name,pass);
    std::lock_guard guard(control_mutex);
    auto live=snapshot();auto login=checked_app_login(*live,appid,token);const auto& service=live->services.at(login.login.service_id);
    auto current=live->users.find(user.id);
    if(current==live->users.end()||current->second.hash!=user.hash||!permitted(service,current->second))throw HttpError(403,"账号已停用或无服务访问权限");
    audit(task,user.username,"login.success","appid="+appid);
    {
        std::lock_guard lock(flow_mutex);auto key=sha256(token);auto used=used_login_tokens.find(key);
        if(used!=used_login_tokens.end()&&used->second>now())throw HttpError(410,"登录 Token 已使用");
        if(!login.flow_id.empty()&&!flows.count(login.flow_id))throw HttpError(410,"登录 Token 已使用");
        if(used_login_tokens.size()>=20000)throw HttpError(503,"登录请求过多，请稍后重试");
        used_login_tokens[key]=login.expires;
        if(!login.flow_id.empty())flows.erase(login.flow_id);
    }
    auto [session,binding,lifetime]=issue_session(task,current->second,service.host,login.login.protocol,service.id,false);
    (void)lifetime;
    respond(task,200,{{"result","Ok"},{"retmsg","登录成功"},
        {"cookie","__Host-gateway_session="+session+"; "+BINDING_COOKIE+"="+binding}});
}
static void authenticate(WFHttpTask *task, bool nginx) {
    ++auth_requests;
    auto c=snapshot();
    auto host=header(task,"X-Forwarded-Host"), uri=header(task,"X-Forwarded-Uri");
    if(redirect_disabled_service(task,*c,host,header(task,"X-Forwarded-Method"),nginx)){++auth_rejected;return;}
    auto& s=service_by_host(*c,host);
    if (!valid_path(uri)) throw HttpError(400,"请求地址无效");
    auto user=current_user(task,*c,false);
    long long expires=0;
    ClientProtocol protocol;
    bool refresh_session=false;
    if(!user.id.empty()){
        std::shared_lock lock(session_mutex);auto found=sessions.find(session_key(task));
        if(found==sessions.end() || found->second.service_id!=s.id || !session_is_alive(session_expiry(found->second,*c),now()))
            user={"","","","","",false};
        else {
            auto& session=found->second;
            protocol=session.protocol;expires=session_expiry(session,*c);
            refresh_session=session.cookie_lifetime!=s.cookie_lifetime || now()-session.cookie_refreshed>=86400;
        }
    }
    if(refresh_session){
        std::unique_lock lock(session_mutex);auto found=sessions.find(session_key(task));
        if(found!=sessions.end()){found->second.cookie_lifetime=s.cookie_lifetime;found->second.cookie_refreshed=now();}
    }
    if (user.id.empty() && !excluded_path(s,uri)) {
        ++auth_rejected;
        std::string login=make_login_request(task,s,uri);
        task->get_resp()->set_header_pair("X-Gateway-Login",login);
        auto method=header(task,"X-Forwarded-Method");
        if (!nginx && (method=="GET" || method=="HEAD")) redirect(task,login);
        else respond(task,401,{{"error","请先登录"},{"login_url",login}});
        return;
    }
    if (!user.id.empty() && !permitted(s,user)) throw HttpError(403,"无权访问该服务");
    auto binding=cookie(task,BINDING_COOKIE);bool issue_binding=!valid_cookie_v1(binding);
    if(issue_binding)binding="v1."+random_hex();
    auto t=now();
    auto token_expires=expires==0?t+60:std::min(t+60,expires);
    json claims={{"iss",origin},{"aud",s.host},{"sub",user.id},{"iat",t},{"nbf",t-2},{"exp",token_expires},
        {"authenticated",!user.id.empty()},{"username",user.username},{"display_name",user.name},{"role",user.role},
        {"request_method",header(task,"X-Forwarded-Method")},{"request_uri_sha256",sha256(uri)},
        {"ver",TOKEN_VERSION},{"type","gateway_access"},{"cookie_version",COOKIE_VERSION},{"cookie_name",BINDING_COOKIE},
        {"cookie_sha256",sha256(binding)},{"sid",user.id.empty()?"":session_key(task)},
        {"client_sdk_version",protocol.sdk_version},{"online_only",protocol.online_only},{"appid",s.appid}};
    auto *resp=task->get_resp();
    resp->set_status_code("200");
    resp->set_header_pair("X-Gateway-Upstream",s.target.address);
    resp->set_header_pair("X-Gateway-Transport",s.target.scheme);
    resp->set_header_pair("X-Gateway-TLS-Name",s.target.hostname);
    resp->set_header_pair("X-Gateway-Backend-Host",s.target.address);
    resp->set_header_pair("X-Gateway-Cookie",clean_cookies(task,binding));
    auto remaining=expires==0?0:std::max(1LL,expires-t);
    resp->set_header_pair("X-Gateway-Set-Cookie",issue_binding||refresh_session?cookie_header_value(BINDING_COOKIE,binding,user.id.empty()?s.cookie_lifetime:remaining):"");
    resp->set_header_pair("X-Gateway-Set-Session-Cookie",refresh_session?cookie_header_value("__Host-gateway_session",cookie(task,"__Host-gateway_session"),remaining):"");
    resp->set_header_pair("X-Gateway-Token",sign_jwt(claims,s.secret));
    resp->set_header_pair("X-Gateway-User",user.username);
    resp->set_header_pair("X-Gateway-User-Id",user.id);
    resp->set_header_pair("X-Gateway-Role",user.role);
    resp->set_header_pair("X-Gateway-User-Info",base64url(claims.dump()));
    ++auth_granted;
}
static void verify_backend_request(WFHttpTask *task,const Config& c) {
    if(header(task,"Content-Type").rfind("application/json",0)!=0)throw HttpError(400,"Expected application/json");
    auto b=body(task);auto audience=text_field(b,"audience",1,253);
    auto found=c.hosts.find(audience);
    if(found==c.hosts.end()) {respond(task,401,{{"valid",false},{"error","Verification authentication failed"}});return;}
    const auto& service=c.services.at(found->second);
    if(!secure_equal(header(task,"Authorization"),"Bearer "+verification_key(service.secret))) {
        respond(task,401,{{"valid",false},{"error","Verification authentication failed"}});return;
    }
    try {
        if(!service.enabled)throw std::invalid_argument("Service disabled");
        auto method=text_field(b,"method",1,32),uri=text_field(b,"uri",1,4096);
        auto token=text_field(b,"token",1,16384),cookies=text_field(b,"cookie",1,32768);
        auto claims=verify_access_token(token,service.secret,origin,audience,cookies,method,uri);
        if(claims.value("appid",std::string())!=service.appid)throw std::invalid_argument("AppID changed");
        if(claims["authenticated"].get<bool>()) {
            std::string uid;
            {std::shared_lock lock(session_mutex);auto it=sessions.find(claims["sid"].get<std::string>());
             if(it==sessions.end() || !session_is_alive(session_expiry(it->second,c),now()) || it->second.host!=audience ||
                it->second.service_id!=service.id ||
                !secure_equal(it->second.binding_hash,claims["cookie_sha256"]))throw std::invalid_argument("Session revoked");
             uid=it->second.user_id;}
            auto user=c.users.find(uid);
            if(user==c.users.end() || claims["sub"]!=uid || !permitted(service,user->second) ||
                claims["username"]!=user->second.username || claims["role"]!=user->second.role)
                throw std::invalid_argument("User access revoked");
            {std::unique_lock lock(session_mutex);auto session=sessions.find(claims["sid"].get<std::string>());
             if(session!=sessions.end())session->second.last_seen=std::max(session->second.last_seen,now());}
        } else if(!excluded_path(service,uri))throw std::invalid_argument("Anonymous access no longer permitted");
        respond(task,200,{{"valid",true},{"version",TOKEN_VERSION},{"verified_at",now()},{"claims",claims},
            {"token_sha256",sha256(token)},{"cookie_header_sha256",sha256(cookies)},
            {"request_method",method},{"request_uri_sha256",sha256(uri)}});
    } catch(const HttpError&) {throw;}
      catch(const std::exception&) {respond(task,401,{{"valid",false},{"error","Invalid token, cookie, request or session"}});}
}
static std::string authorization_url(const Config& c, const User& user, const std::string& request) {
    auto [id,flow]=checked_flow(request);
    std::string ticket=random_hex(), host;
    {
        std::lock_guard lock(flow_mutex); auto it=flows.find(id);
        if (it==flows.end() || it->second.expires<=now()) throw HttpError(410,"登录请求已过期，请重新打开原服务");
        auto service=c.services.find(it->second.service_id);
        if (service==c.services.end() || !service->second.enabled) throw HttpError(403,"服务已停用");
        if (!permitted(service->second,user)) throw HttpError(403,"无权访问该服务");
        it->second.ticket_hash=sha256(ticket); it->second.user_id=user.id; it->second.ticket_expires=now()+30;
        host=service->second.host;
    }
    return "https://"+host+"/_gateway/callback?flow="+id+"&ticket="+ticket;
}
static void callback(WFHttpTask *task, const Config& c, const std::string& id, const std::string& ticket) {
    if (id.size()!=64 || ticket.size()!=64) throw HttpError(400,"登录凭据无效");
    const auto host=header(task,"Host");
    const auto& service=service_by_host(c,host);
    std::string uid,path;ClientProtocol protocol;
    {
        std::lock_guard lock(flow_mutex); auto it=flows.find(id);
        if (it==flows.end()) throw HttpError(410,"登录凭据已使用或已过期");
        auto& f=it->second;
        if (f.service_id!=service.id || f.expires<=now() || f.ticket_expires<=now() ||
            f.ticket_hash!=sha256(ticket) || f.verifier_hash!=sha256(cookie(task,"__Host-gateway_flow_"+id.substr(0,16))))
            throw HttpError(403,"登录凭据校验失败");
        uid=f.user_id; path=f.path;protocol=f.protocol; flows.erase(it);
    }
    auto u=c.users.find(uid);
    if (u==c.users.end() || !permitted(service,u->second)) throw HttpError(403,"账号已停用或无访问权限");
    new_session(task,u->second,protocol,service.id);
    set_cookie(task,"__Host-gateway_flow_"+id.substr(0,16),"",0);
    redirect(task,path);
}
static json session_list(const Config& c) {
    json result=json::array(); std::shared_lock lock(session_mutex);
    for (const auto& [key,s]:sessions) {
        auto expires=session_expiry(s,c);
        if (!session_is_alive(expires,now())) continue;
        auto u=c.users.find(s.user_id); if (u==c.users.end()) continue;
        const Service *service=s.service_id.empty()?nullptr:&c.services.at(s.service_id);
        if(!u->second.enabled || (service && !permitted(*service,u->second))) continue;
        result.push_back({{"id",key},{"user_id",s.user_id},{"username",u->second.username},
            {"ip",s.ip},{"created_at",s.created},{"expires_at",expires},{"host",s.host},
            {"service_id",s.service_id},{"appid",service?service->appid:""},{"service_name",service?service->name:"Gateway 控制台"},
            {"scope",service&&service->builtin?"admin":"service"},{"last_seen_at",s.last_seen},
            {"online",session_is_online(s.last_seen,now())},{"user_agent",s.client.user_agent},{"app_package",s.client.app_package}});
    }
    return result;
}
static void validate_service(const json& b, const Config& c, const std::string& id) {
    auto current=c.services.find(id);
    const bool builtin=current!=c.services.end()&&current->second.builtin;
    if(b.contains("cookie_max_age_hours")){
        if(!b["cookie_max_age_hours"].is_number())throw HttpError(400,"Cookie 有效期必须是小时数");
        try{cookie_seconds_from_hours(b["cookie_max_age_hours"].get<double>());}
        catch(const std::exception&){throw HttpError(400,"Cookie 有效期必须为 0 至 876000 小时，0 表示无限");}
    }
    auto appid=text_field(b,"appid",1,64);
    if(appid=="gateway-console"&&!builtin)throw HttpError(400,"该 AppID 保留给内置控制台");
    static const std::regex appid_pattern(R"(^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$)");
    if(!std::regex_match(appid,appid_pattern))throw HttpError(400,"AppID 仅支持字母、数字、下划线、点和连字符");
    auto existing=c.appids.find(appid);
    if(existing!=c.appids.end()&&existing->second!=id)throw HttpError(409,"AppID 已被使用");
    text_field(b,"name",1,128); auto host=text_field(b,"host",1,253);
    if (!valid_host(host) || (host==public_host&&!builtin)) throw HttpError(400,"请输入有效的业务域名，不能使用网关自身域名");
    std::string reserved=","+env("GATEWAY_RESERVED_HOSTS")+",";
    if (reserved.find(","+host+",")!=std::string::npos) throw HttpError(400,"该域名已有独立 Caddy 站点，请先迁移原站点配置");
    auto it=c.hosts.find(host);
    if (it!=c.hosts.end() && it->second!=id) throw HttpError(409,"该域名已经配置");
    auto target=parse_upstream(text_field(b,"upstream",1,512));
    if (!builtin&&(target.hostname==public_host || target.address=="127.0.0.1:19090" || target.address=="localhost:19090"))
        throw HttpError(400,"后端地址不能指向网关自身");
    if (!b.contains("excluded_paths") || !b["excluded_paths"].is_array() || b["excluded_paths"].size()>100)
        throw HttpError(400,"免登录路径最多 100 条");
    for (const auto& r:b["excluded_paths"]) {
        if (!r.is_string()) throw HttpError(400,"免登录路径格式无效");
        auto rule=r.get<std::string>();
        auto check=rule.size()>=2 && rule.substr(rule.size()-2)=="/*" ? rule.substr(0,rule.size()-1) : rule;
        if (!valid_path(check) || check.find_first_of("?%*")!=std::string::npos || check.find("//")!=std::string::npos ||
            check.find("/./")!=std::string::npos || check.find("/../")!=std::string::npos || check.rfind("/_gateway",0)==0)
            throw HttpError(400,"免登录路径应为精确路径或以 /* 结尾的前缀");
    }
    if (!b.contains("users") || !b["users"].is_array() || b["users"].size()>10000) throw HttpError(400,"用户列表无效");
    for (const auto& u:b["users"]) if (!u.is_string() || !c.users.count(u.get<std::string>())) throw HttpError(400,"用户不存在");
    if (!b.contains("enabled") || !b["enabled"].is_boolean() || !b.contains("allow_all") || !b["allow_all"].is_boolean())
        throw HttpError(400,"服务开关格式无效");
    if(builtin){
        const auto& fixed=current->second;
        if(appid!=fixed.appid||host!=fixed.host||b["name"]!=fixed.name||b["upstream"]!=fixed.upstream||!b["enabled"].get<bool>()||!b["excluded_paths"].empty())
            throw HttpError(400,"内置控制台的标识、路由及启用状态不能修改");
        for(const auto& [uid,user]:c.users)
            if(user.role=="admin"&&std::find(b["users"].begin(),b["users"].end(),json(uid))==b["users"].end())
                throw HttpError(400,"管理员的控制台登录权限不能移除");
    }
}
static void mutate_service(WFHttpTask *task, const json& b, const std::string& id, const User& actor) {
    auto c=snapshot(); validate_service(b,*c,id);
    if(!id.empty()&&!c->services.count(id))throw HttpError(404,"服务不存在");
    auto lifetime=b.contains("cookie_max_age_hours")?cookie_seconds_from_hours(b["cookie_max_age_hours"].get<double>()):
        (id.empty()?DEFAULT_SERVICE_COOKIE_SECONDS:c->services.at(id).cookie_lifetime);
    auto& d=db(); d.begin(); std::string saved=id;
    try {
        std::vector<std::string> values={b["name"],b["host"],b["upstream"],b["excluded_paths"].dump(),
            b["enabled"].get<bool>()?"1":"0",b["allow_all"].get<bool>()?"1":"0"};
        values.push_back(b["appid"]);
        values.push_back(std::to_string(lifetime));
        if (id.empty()) {
            values.push_back(random_hex());
            d.query("INSERT INTO services(name,host,upstream,excluded_paths,enabled,allow_all,appid,cookie_max_age_seconds,token_secret) VALUES(?,?,?,?,?,?,?,?,?)",values);
            saved=std::to_string(d.inserted());
        } else {
            if (!c->services.count(id)) throw HttpError(404,"服务不存在");
            values.push_back(id);
            d.query("UPDATE services SET name=?,host=?,upstream=?,excluded_paths=?,enabled=?,allow_all=?,appid=?,cookie_max_age_seconds=? WHERE id=?",values);
            d.query("DELETE FROM service_users WHERE service_id=?",{id});
        }
        for (const auto& u:b["users"]) d.query("INSERT IGNORE INTO service_users(service_id,user_id) VALUES(?,?)",{saved,u.get<std::string>()});
        audit(task,actor.username,id.empty()?"service.create":"service.update",b["host"]);
        d.commit();
    } catch (...) { try { d.rollback(); } catch (...) {} throw; }
    load_config();auto live=snapshot();const auto& service=live->services.at(saved);
    {
        std::unique_lock lock(session_mutex);
        for(auto it=sessions.begin();it!=sessions.end();){
            auto user=live->users.find(it->second.user_id);
            if(it->second.service_id==saved && (!service.enabled || user==live->users.end() || !permitted(service,user->second)))
                it=sessions.erase(it);
            else ++it;
        }
    }
    respond(task,200,{{"id",saved},{"appid",service.appid},{"ok",true}});
}
static void mutate_user(WFHttpTask *task, const json& b, const std::string& id, const User& actor) {
    auto c=snapshot();
    auto username=text_field(b,"username",1,64), name=text_field(b,"display_name",1,128),role=text_field(b,"role",1,16);
    static const std::regex pattern("^[a-zA-Z0-9_.-]{1,64}$");
    if (!std::regex_match(username,pattern) || (role!="admin" && role!="user") || !b.contains("enabled") || !b["enabled"].is_boolean())
        throw HttpError(400,"账号或角色格式无效");
    auto pass=text_field(b,"password",id.empty()?12:0,256); if (!pass.empty() && pass.size()<12) throw HttpError(400,"密码至少 12 个字符");
    if (!id.empty() && !c->users.count(id)) throw HttpError(404,"用户不存在");
    auto found=c->usernames.find(username);
    if (found!=c->usernames.end() && found->second!=id) throw HttpError(409,"用户名已存在");
    if (id==actor.id && (role!="admin" || !b["enabled"].get<bool>())) throw HttpError(400,"不能停用或降级当前管理员");
    auto& d=db(); d.begin();
    try {
        if (id.empty()) d.query("INSERT INTO users(username,display_name,password_hash,role,enabled) VALUES(?,?,?,?,?)",
            {username,name,password_hash(pass),role,b["enabled"].get<bool>()?"1":"0"});
        else {
            d.query("UPDATE users SET username=?,display_name=?,role=?,enabled=? WHERE id=?",{username,name,role,b["enabled"].get<bool>()?"1":"0",id});
            if (!pass.empty()) d.query("UPDATE users SET password_hash=? WHERE id=?",{password_hash(pass),id});
        }
        audit(task,actor.username,id.empty()?"user.create":"user.update",username); d.commit();
    } catch (...) { try { d.rollback(); } catch (...) {} throw; }
    load_config();
    if (!id.empty()) revoke_user(id);
    respond(task,200,{{"ok",true}});
}
static void dispatch(WFHttpTask *task) {
    auto uri=std::string(task->get_req()->get_request_uri()), method=std::string(task->get_req()->get_method());
    auto path=uri.substr(0,uri.find('?')); auto params=query_params(uri); auto host=header(task,"Host");
    auto login_token=params["token"].empty()?params["request"]:params["token"];
    auto c=snapshot();
    if (path=="/healthz" && method=="GET") { respond(task,200,{{"ok",true},{"uptime_seconds",now()-started}}); return; }
    if (path=="/internal/tls-ask" && method=="GET") {
        if (params["domain"]==public_host) task->get_resp()->set_status_code("200");
        else {
            if(!c->hosts.count(params["domain"]))throw HttpError(404,"该域名未接入网关");
            task->get_resp()->set_status_code("200");
        }
        return;
    }
    if ((path=="/internal/auth" || path=="/internal/nginx-auth") && method=="GET") { authenticate(task,path=="/internal/nginx-auth"); return; }
    if((path=="/_gateway/start"||path=="/_gateway/callback")&&method=="GET"&&redirect_disabled_service(task,*c,host,method))return;
    if(path=="/_gateway/start"&&method=="GET"){sdk_start(task,*c,login_token,params["appid"],true);return;}
    if (path=="/_gateway/callback" && method=="GET") { callback(task,*c,params["flow"],params["ticket"]); return; }
    if (host!=public_host) throw HttpError(404,"该地址不提供控制台");
    if((path=="/"||path=="/api/public/notice")&&(method=="GET"||method=="HEAD")){
        json notice=nullptr;
        auto found=c->appids.find(params["appid"]);
        if(params["reason"]=="service_disabled"&&found!=c->appids.end()){
            const auto& service=c->services.at(found->second);
            if(!service.enabled&&!service.builtin){
                disabled_service_headers(task,service);
                notice={{"reason","service_disabled"},{"appid",service.appid},{"name",service.name},{"host",service.host}};
            }
        }
        if(path=="/api/public/notice"){respond(task,200,{{"notice",notice}});return;}
    }
    if(path=="/login/start"&&method=="GET"){sdk_start(task,*c,login_token,params["appid"],false);return;}
    if(path=="/login"&&method=="POST"){app_login(task,*c,params["appid"],params["token"]);return;}
    if(path=="/verify" && method=="POST") {verify_backend_request(task,*c);return;}
    if (method=="GET" && path=="/login") {
        if(!login_token.empty()){
            if(login_token.size()>16384)throw HttpError(400,"登录 Token 过长");
            auto decoded=jwt::decode(login_token);auto claims=json::parse(decoded.get_payload());
            if(claims.value("type",std::string())=="sdk_login"){sdk_start(task,*c,login_token,params["appid"],false);return;}
            auto [id,flow]=checked_flow(login_token);
            if(!params["token"].empty()&&params["appid"]!=c->services.at(flow.service_id).appid)throw HttpError(400,"AppID 与登录 Token 不匹配");
        }
    }
    if (path=="/authorize" && method=="GET") {
        auto [id,flow]=checked_flow(login_token);
        redirect(task,origin+"/login?appid="+c->services.at(flow.service_id).appid+"&token="+encode_url(login_token));return;
    }
    if (path=="/api/public" && method=="GET") {
        auto [id,flow]=checked_flow(login_token);
        auto s=c->services.find(flow.service_id);
        if (s==c->services.end() || !s->second.enabled) throw HttpError(410,"目标服务已停用");
        if(!params["token"].empty()&&params["appid"]!=s->second.appid)throw HttpError(400,"AppID 与登录 Token 不匹配");
        auto user=current_user(task,*c,false);
        json quick_login=nullptr;
        if(!user.id.empty())quick_login={{"user",user_json(user)},{"permitted",permitted(s->second,user)},
            {"csrf",sha256("csrf:"+cookie(task,"__Host-gateway_session"))}};
        respond(task,200,{{"service",{{"id",s->second.id},{"appid",s->second.appid},{"name",s->second.name},{"host",s->second.host}}},
            {"return_url","https://"+s->second.host+flow.path},{"expires_at",flow.expires},
            {"sdk_version",flow.protocol.sdk_version},{"token_version",flow.protocol.token_version},
            {"cookie_version",flow.protocol.cookie_version},{"online_only",flow.protocol.online_only},{"quick_login",quick_login}}); return;
    }
    if (path=="/api/login/quick" && method=="POST") {
        std::lock_guard lock(control_mutex);
        auto live=snapshot();auto user=current_user(task,*live);
        csrf(task,true);rate_limit("quick-login:"+user.id,30);
        auto b=body(task);auto request=text_field(b,"token",1,16384);
        auto [id,flow]=checked_flow(request);const auto& service=live->services.at(flow.service_id);
        if(b.contains("appid")&&b.at("appid")!=service.appid)throw HttpError(400,"AppID 与登录 Token 不匹配");
        if(!permitted(service,user))throw HttpError(403,"当前账号无权访问目标服务，请切换账号");
        audit(task,user.username,"login.success","appid="+service.appid+"; method=quick");
        respond(task,200,{{"redirect",authorization_url(*live,user,request)}});return;
    }
    if (path=="/api/login" && method=="POST") {
        csrf(task,false); auto b=body(task);
        auto name=text_field(b,"username",1,64), pass=text_field(b,"password",1,256);
        auto verified=password_user(task,*c,name,pass);const auto *u=&verified;
        std::string request=b.value("token",b.value("request",std::string())), mode=b.value("mode",std::string());
        std::string target="/admin";
        if (mode=="admin") {
            std::lock_guard lock(control_mutex);auto live=snapshot();auto current=live->users.find(u->id);
            if(current==live->users.end()||current->second.hash!=u->hash||!permitted(console_service(*live),current->second))
                throw HttpError(403,"该账号没有控制台登录权限");
            audit(task,u->username,"login.success","scope=admin");new_session(task,*u);
        } else {
            std::lock_guard lock(control_mutex);auto live=snapshot();auto current=live->users.find(u->id);
            if(current==live->users.end()||!current->second.enabled||current->second.hash!=u->hash)throw HttpError(401,"账号状态已变更，请重新登录");
            auto [id,flow]=checked_flow(request);auto s=live->services.find(flow.service_id);
            if (s==live->services.end() || !s->second.enabled || !permitted(s->second,*u)) throw HttpError(403,"无权访问目标服务");
            if(b.contains("appid")&&b.at("appid")!=s->second.appid)throw HttpError(400,"AppID 与登录 Token 不匹配");
            audit(task,u->username,"login.success","appid="+s->second.appid);
            target=authorization_url(*live,current->second,request);
        }
        respond(task,200,{{"redirect",target}}); return;
    }
    if (path=="/api/me" && method=="GET") {
        auto u=current_user(task,*c);
        respond(task,200,{{"user",user_json(u)},{"csrf",sha256("csrf:"+cookie(task,"__Host-gateway_session"))}}); return;
    }
    if (path.rfind("/api/",0)==0) {
        auto u=current_user(task,*c); bool write=method!="GET";
        if (write) csrf(task,true);
        if (path=="/api/logout" && method=="POST") {
            revoke_user(u.id); set_cookie(task,"__Host-gateway_session","",0); audit(task,u.username,"logout","");
            respond(task,200,{{"ok",true}}); return;
        }
        if (path=="/api/password" && method=="POST") {
            rate_limit("password:"+u.id,5); auto b=body(task);
            auto old=text_field(b,"old_password",1,256),pass=text_field(b,"new_password",12,256);
            if (!password_verify(old,u.hash)) throw HttpError(400,"当前密码错误");
            std::lock_guard lock(control_mutex);
            auto live=current_user(task,*snapshot());
            if (live.hash!=u.hash) throw HttpError(401,"账号状态已变更，请重新登录");
            db().query("UPDATE users SET password_hash=? WHERE id=?",{password_hash(pass),u.id});
            load_config(); revoke_user(u.id); audit(task,u.username,"password.changed","");
            set_cookie(task,"__Host-gateway_session","",0); respond(task,200,{{"ok",true}}); return;
        }
        if (u.role!="admin") throw HttpError(403,"需要管理员权限");
        if (path=="/api/admin/state" && method=="GET") {
            json services=json::array(), users=json::array();
            for (const auto& [id,s]:c->services) services.push_back(service_json(s));
            for (const auto& [id,user]:c->users) users.push_back(user_json(user));
            auto active_sessions=session_list(*c);
            auto online=std::count_if(active_sessions.begin(),active_sessions.end(),[](const json& s){return s["online"].get<bool>();});
            respond(task,200,{{"services",services},{"users",users},{"sessions",active_sessions},
                {"metrics",{{"uptime_seconds",now()-started},{"auth_requests",auth_requests.load()},
                {"auth_granted",auth_granted.load()},{"auth_rejected",auth_rejected.load()},
                {"online_sessions",online},{"valid_sessions",active_sessions.size()}}}}); return;
        }
        if (path=="/api/admin/audit" && method=="GET") {
            json entries=json::array();
            for (const auto& r:db().query("SELECT id,actor,action,detail,ip,created_at,user_agent,app_package FROM audit_logs ORDER BY id DESC LIMIT 100"))
                entries.push_back({{"id",r[0]},{"actor",r[1]},{"action",r[2]},{"detail",r[3]},{"ip",r[4]},{"created_at",r[5]},
                    {"user_agent",r[6]},{"app_package",r[7]}});
            respond(task,200,{{"entries",entries}}); return;
        }
        std::lock_guard lock(control_mutex);
        current_user(task,*snapshot());
        if (snapshot()->users.at(u.id).role!="admin") throw HttpError(403,"需要管理员权限");
        if(path.rfind("/api/admin/sessions/",0)==0 && method=="DELETE"){
            auto key=path.substr(std::string("/api/admin/sessions/").size());
            if(key.size()!=64)throw HttpError(400,"会话标识无效");
            std::string detail;
            {std::shared_lock lock(session_mutex);auto found=sessions.find(key);
             if(found==sessions.end())throw HttpError(404,"会话不存在或已失效");
             detail=found->second.host;}
            audit(task,u.username,"session.revoke",detail);
            {std::unique_lock lock(session_mutex);sessions.erase(key);}
            respond(task,200,{{"ok",true}});return;
        }
        static const std::regex service_route(R"(^/api/admin/services(?:/([0-9]+))?(?:/(secret|rotate))?$)"),
            user_route(R"(^/api/admin/users(?:/([0-9]+))?(?:/(revoke))?$)");
        std::smatch match;
        if (std::regex_match(path,match,service_route)) {
            std::string id=match[1],op=match[2];
            if ((method=="POST" && id.empty()) || (method=="PUT" && !id.empty() && op.empty())) {
                mutate_service(task,body(task),id,u); return;
            }
            auto live=snapshot(); auto s=live->services.find(id);
            if (s==live->services.end()) throw HttpError(404,"服务不存在");
            if(s->second.builtin)throw HttpError(403,"内置控制台不能删除，也不提供后端签名密钥");
            if (method=="DELETE" && op.empty()) {
                db().query("DELETE FROM services WHERE id=?",{id}); load_config(); audit(task,u.username,"service.delete",s->second.host);
                respond(task,200,{{"ok",true}}); return;
            }
            if (method=="POST" && op=="secret") {
                audit(task,u.username,"service.secret.read",s->second.host);
                respond(task,200,{{"appid",s->second.appid},{"secret",s->second.secret},{"verification_key",verification_key(s->second.secret)},
                    {"token_version",TOKEN_VERSION},{"cookie_version",COOKIE_VERSION},{"verify_url",origin+"/verify"},
                    {"algorithm","HS256"},{"audience",s->second.host},{"issuer",origin}}); return;
            }
            if (method=="POST" && op=="rotate") {
                auto secret=random_hex(); db().query("UPDATE services SET token_secret=? WHERE id=?",{secret,id});
                load_config(); audit(task,u.username,"service.secret.rotate",s->second.host);
                respond(task,200,{{"appid",s->second.appid},{"secret",secret}}); return;
            }
        }
        if (std::regex_match(path,match,user_route)) {
            std::string id=match[1],op=match[2];
            if ((method=="POST" && id.empty()) || (method=="PUT" && !id.empty() && op.empty())) {
                mutate_user(task,body(task),id,u); return;
            }
            if (method=="POST" && op=="revoke") {
                revoke_user(id); audit(task,u.username,"sessions.revoke",id); respond(task,200,{{"ok",true}}); return;
            }
            if (method=="DELETE" && !id.empty() && op.empty()) {
                if (id==u.id) throw HttpError(400,"不能删除当前管理员");
                db().query("DELETE FROM users WHERE id=?",{id});load_config();revoke_user(id);
                audit(task,u.username,"user.delete",id);respond(task,200,{{"ok",true}});return;
            }
        }
        throw HttpError(404,"接口不存在");
    }
    if (method!="GET" && method!="HEAD") throw HttpError(405,"请求方法不支持");
    if (path=="/index.html") { redirect(task,"/"); return; }
    auto asset=assets.find(path);
    if (path=="/" || path=="/login" || path=="/admin") asset=assets.find("/index.html");
    if (asset==assets.end()) throw HttpError(404,"页面不存在");
    task->get_resp()->set_header_pair("Content-Type",asset->second.first);
    if (method!="HEAD") task->get_resp()->append_output_body(asset->second.second);
}
static void respond_error(WFHttpTask *task,int status,const std::string& message) {
    auto uri=std::string(task->get_req()->get_request_uri());
    if(std::string(task->get_req()->get_method())=="POST"&&uri.substr(0,uri.find('?'))=="/login")
        respond(task,status,{{"result","Failed"},{"retmsg",message},{"cookie",""}});
    else respond(task,status,{{"error",message}});
}
static void safely(WFHttpTask *task) {
    try { dispatch(task); }
    catch (const HttpError& e) { respond_error(task,e.status,e.what()); }
    catch (const json::exception&) { respond_error(task,400,"字段格式无效"); }
    catch (const std::invalid_argument&) { respond_error(task,400,"请求参数或登录凭据无效"); }
    catch (const DbError& e) {
        std::cerr<<"database: code="<<e.code()<<" "<<e.what()<<'\n'; reset_db();
        respond_error(task,503,"数据库暂时不可用，请稍后重试");
    }
    catch (const std::exception& e) {
        std::cerr<<"request: "<<e.what()<<'\n'; respond_error(task,500,"服务暂时不可用");
    }
}
static void process(WFHttpTask *task) {
    auto *r=task->get_resp(); r->set_http_version("HTTP/1.1"); r->set_status_code("200");
    r->set_header_pair("Cache-Control","no-store");
    r->set_header_pair("X-Content-Type-Options","nosniff");
    r->set_header_pair("Referrer-Policy","no-referrer");
    r->set_header_pair("X-Frame-Options","DENY");
    r->set_header_pair("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    auto path=std::string(task->get_req()->get_request_uri()); path=path.substr(0,path.find('?'));
    bool slow=(path=="/login"&&std::string(task->get_req()->get_method())=="POST") || path=="/api/login" || path=="/api/login/quick" || path=="/api/logout" || path=="/api/password" || path.rfind("/api/admin/",0)==0;
    if (!slow) { safely(task); return; }
    if (pending.fetch_add(1)>=128) {
        --pending; respond_error(task,503,"服务繁忙，请稍后重试"); return;
    }
    static std::atomic<unsigned> queue{0};
    *series_of(task) << WFTaskFactory::create_go_task("gateway-control-"+std::to_string(queue++%8),[task] {
        safely(task); --pending;
    });
}
static void bootstrap() {
    if (!db().query("SELECT id FROM users LIMIT 1").empty()) return;
    auto pass=random_hex(12); auto path=state_dir+"/initial-admin.txt";
    int fd=open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    if (fd<0) throw std::runtime_error("Cannot create initial-admin.txt; inspect existing file before retrying");
    std::string content="URL: "+origin+"/admin\nUsername: admin\nPassword: "+pass+"\n";
    if (write(fd,content.data(),content.size())!=static_cast<ssize_t>(content.size()) || fsync(fd)!=0) {
        close(fd); throw std::runtime_error("Cannot write initial admin credentials");
    }
    close(fd);
    db().query("INSERT INTO users(username,display_name,password_hash,role) VALUES('admin','管理员',?,'admin')",{password_hash(pass)});
    std::cout<<"Initial admin credentials written to "<<path<<'\n';
}
static void bootstrap_console() {
    auto existing=db().query("SELECT appid FROM services WHERE host=?",{public_host});
    if(!existing.empty()){
        if(existing[0][0]!="gateway-console")throw std::runtime_error("Console service has an unexpected AppID");
        return;
    }
    db().query("INSERT INTO services(appid,name,host,upstream,excluded_paths,token_secret,enabled,allow_all,cookie_max_age_seconds) VALUES(?,?,?,?,?,?,1,0,?)",
        {"gateway-console","Gateway 控制台",public_host,origin,"[]",random_hex(),std::to_string(session_lifetime)});
}
int main() {
    try {
        public_host=env("GATEWAY_HOST","gateway.example.com"); origin="https://"+public_host;
        if (!valid_host(public_host)) throw std::runtime_error("Invalid GATEWAY_HOST");
        web_root=env("GATEWAY_WEB_ROOT","web"); state_dir=env("GATEWAY_STATE_DIR","/var/lib/gateway");
        session_lifetime=std::stoll(env("GATEWAY_SESSION_SECONDS","43200"));
        if (session_lifetime<300 || session_lifetime>604800) throw std::runtime_error("Session lifetime must be 300..604800 seconds");
        sigset_t signals; sigemptyset(&signals); sigaddset(&signals,SIGINT); sigaddset(&signals,SIGTERM);
        pthread_sigmask(SIG_BLOCK,&signals,nullptr); signal(SIGPIPE,SIG_IGN);
        mysql_library_init(0,nullptr,nullptr);
        if (env("DB_TLS_REQUIRED","true")=="false")
            std::cerr<<"Database TLS enforcement is disabled by configuration\n";
        bootstrap(); bootstrap_console(); load_config();
        for (const auto& [name,type]:std::vector<std::pair<std::string,std::string>>{
            {"index.html","text/html; charset=utf-8"},{"app.css","text/css; charset=utf-8"},
            {"app.js","text/javascript; charset=utf-8"},{"components.js","text/javascript; charset=utf-8"},{"lucide.min.js","text/javascript; charset=utf-8"}}) {
            std::ifstream in(web_root+"/"+name,std::ios::binary);
            if (!in) throw std::runtime_error("Missing web asset: "+name);
            assets["/"+name]={type,std::string(std::istreambuf_iterator<char>(in),{})};
        }
        auto settings=GLOBAL_SETTINGS_DEFAULT; settings.poller_threads=2; settings.handler_threads=4; settings.compute_threads=8;
        WORKFLOW_library_init(&settings);
        auto params=HTTP_SERVER_PARAMS_DEFAULT; params.request_size_limit=128*1024; params.max_connections=4096;
        WFHttpServer server(&params,process);
        if (server.start("127.0.0.1",std::stoi(env("GATEWAY_PORT","19090")))!=0) throw std::runtime_error("Cannot bind gateway port");
        std::mutex cleaner_mutex; std::condition_variable cleaner_cv; bool stop=false;
        std::thread cleaner([&] {
            std::unique_lock lock(cleaner_mutex);
            while (!cleaner_cv.wait_for(lock,std::chrono::seconds(30),[&]{return stop;})) {
                auto t=now();
                { auto c=snapshot();std::unique_lock guard(session_mutex);
                  for (auto it=sessions.begin();it!=sessions.end();) if (!session_is_alive(session_expiry(it->second,*c),t)) it=sessions.erase(it); else ++it; }
                { std::lock_guard guard(flow_mutex);
                  for (auto it=flows.begin();it!=flows.end();) if (it->second.expires<=t) it=flows.erase(it); else ++it;
                  for (auto it=used_login_tokens.begin();it!=used_login_tokens.end();) if (it->second<=t) it=used_login_tokens.erase(it); else ++it; }
            }
        });
        std::cout<<"Gateway listening on 127.0.0.1:"<<env("GATEWAY_PORT","19090")<<std::endl;
        int sig; sigwait(&signals,&sig); server.stop();
        { std::lock_guard lock(cleaner_mutex); stop=true; } cleaner_cv.notify_all(); cleaner.join();
    } catch (const std::exception& e) { std::cerr<<"startup: "<<e.what()<<'\n'; return 1; }
}

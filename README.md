# Gateway

SDK 推荐使用 `checkCookie(request, appid, secret, 是否302, 是否允许在线回退)`，Python 包名为 `gateway_sdk`，C++ 命名空间为 `gateway::sdk`，静态库为 `libgateway_sdk.a`。返回结构中的 `result` 只有 `Ok` 和 `redictionToLogin`，原因放 `error`，失败登录地址放 `redictUrl`。完整用法见 [SDK 文档](../gateway-sdk/README.md)。

SDK 登录请求通过 `/login?appid=...&token=...` 携带签名保护的 AppID、返回地址、时间戳、有效期和版本能力；网关协商后进入统一登录页，页面上的目标服务无法修改。`POST /login` 提供无需浏览器跳转的 App 登录，参数为 `appid`、`username`、`passwd`、`token`，成功返回 `{"result":"Ok","retmsg":"登录成功","cookie":"..."}`，失败返回 `Failed`、原因和空 Cookie。Token 可由 SDK 的 `createLoginToken(appid, secret, uri)` 生成，成功消费一次；完整接口说明见 SDK 文档。

C++17 + 搜狗 Workflow 的认证网关，前端是原生 HTML / CSS / JavaScript。无 Node、Python、Java 或 Go 应用运行时。现有 Caddy 负责 TLS 和流式反向代理；C++ 负责每次请求的认证、路由选择和 JWT 签发。

## 地址

- `https://gateway.perfy576.com/`：公开状态展示页，不登录、不选择后端。
- `https://gateway.perfy576.com/admin`：管理员登录及控制台。
- `https://gateway.perfy576.com/login?appid=...&token=...`：从业务域名跳转来的统一登录页。目标服务不可修改。

初始管理员用户名为 `admin`。密码保存在服务器文件中：

```bash
sudo cat /var/lib/gateway/initial-admin.txt
```

修改密码位于控制台的「账号安全」。修改密码、停用账号、撤销会话、退出登录都会撤销该用户在所有接入服务上的会话。

## 接入服务

1. 把业务域名 DNS 的 A/AAAA 记录指向本机，确保 80/443 可达；不要保留错误的 AAAA 记录。
2. 在 `/admin` 的「域名与服务」添加名称、自定义且唯一的 AppID、业务域名和后端地址，例如 `https://app.example.com` 对应 `http://10.0.0.8:8080` 或 `https://remote.example.com:8443`。域名字段只填 `app.example.com`。AppID 为 1 至 64 位字母、数字、下划线、点或连字符，首位为字母或数字，区分大小写。
3. 根据需要填写免登录路径，每行一条，例如 `/healthz`、`/assets/*`。前者是精确匹配，后者匹配 `/assets/` 下的内容，不会匹配 `/assets-other`。可配置 `/*` 放开整个域名。编码歧义、点段和重复斜杠不能命中免登录规则。
4. 可允许全部已登录用户，或者限定用户列表。管理员具有服务访问权。即使是免登录路径，也会经过网关，并携带签名的匿名身份。
5. 点击服务行的钥匙按钮查看 AppID 和系统生成的 Secret，把它们配置到后端。界面可更换 Secret，系统仅保留当前一个。

配置保存后立即生效，无需重启 C++ 或重载 Caddy。Caddy 只为内存配置中已启用的业务域名按需申请证书。停用、删除服务立即停止转发；已签发的证书可能仍在 Caddy 的证书缓存中，但不授予访问权。

当前原有 `note.perfy576.com`、`agent.perfy576.com` 的 Caddy 站点保持原状，作为保留域名不能重复接入。要让网关接管它们，需要先迁移 `/etc/caddy/Caddyfile` 中原站点的转发规则，并更新 `/etc/gateway.env` 中的 `GATEWAY_RESERVED_HOSTS`。

## 登录与会话

```mermaid
sequenceDiagram
    participant B as 浏览器
    participant C as Caddy
    participant G as C++ Gateway
    participant A as 后端服务
    B->>C: 访问业务域名 /path?query
    C->>G: 认证子请求（不转发正文）
    G-->>B: 302 /login?appid=服务ID&token=签名请求 + 浏览器绑定 Cookie
    B->>G: 登录（只读目标服务）
    G-->>B: 一次性回跳凭据
    B->>C: 业务域名 /_gateway/callback
    C->>G: 消费回跳凭据 + 校验浏览器 Cookie
    G-->>B: 设置业务域名会话 Cookie，回到原路径
    B->>C: 重新访问原路径
    C->>G: 校验内存会话，签发后端 JWT
    C->>A: 原请求 + X-Gateway-Token
    A-->>B: 响应（支持 WebSocket / SSE）
```

- 密码：OpenSSL scrypt，独立随机盐，`N=16384, r=8, p=1`。
- 会话：256 位密码学随机凭据，值为 `v1.<64位hex>`，内存只记录 SHA-256 摘要，默认 12 小时绝对有效期。Cookie 使用 `__Host-`、`Secure`、`HttpOnly`、`SameSite=Lax`，无共享 Domain。登录态还绑定独立的 `__Host-gateway_binding` Cookie 和域名。
- 登录请求：HS256 签名，包含 `ver=1`、`type=login_request`、`appid`、`service_id`、完整 `return_url`、`iat`、`exp`、`jti`，5 分钟过期；JWT 头包含 `gwv=1`。内存同时保存对应摘要和目标信息。浏览器请求使用服务 Secret 通过 `gateway/browser-login/v1` 派生的密钥；SDK 请求使用独立上下文 `gateway/sdk-login/v1`，防止混用。重启后浏览器流程和已签发会话失效。
- 回跳：一次性随机 ticket，30 秒过期，绑定原浏览器、服务和登录请求；消费后删除。
- 已有中央登录会话可以自动完成后续业务域名的登录。
- 会话、浏览器登录流程、ticket 和接口 Token 已用标记都只在内存里；重启后会话与浏览器流程失效，已用标记清空。SDK 自签 Token 仍受 5 分钟有效期约束。用户、服务配置、后端签名密钥和审计记录在 MySQL 中。
- 无登录态的 GET/HEAD 重定向；POST/PUT 等请求返回 401 和 `login_url` / `X-Gateway-Login`，避免静默丢失正文。
- 认证请求不访问 MySQL。密码校验、管理和审计使用独立工作线程，控制请求队列有容量限制。

## 后端验证

网关转发以下请求头，外部传入的同名头会先清除：

| Header | 含义 |
| --- | --- |
| `X-Gateway-Token` | 标准 JWT HS256，后端据此验证请求和读取身份 |
| `X-Gateway-User-Id` | 用户 ID |
| `X-Gateway-User` | 用户名 |
| `X-Gateway-Role` | 角色 |
| `X-Gateway-User-Info` | JWT claims JSON 的 Base64URL 表示，仅作为便利字段 |

JWT 的示例 payload：

```json
{
  "iss": "https://gateway.perfy576.com",
  "appid": "my-app",
  "ver": 1,
  "type": "gateway_access",
  "cookie_version": 1,
  "cookie_name": "__Host-gateway_binding",
  "cookie_sha256": "<绑定 Cookie 完整值的 SHA-256 摘要>",
  "sid": "<会话凭据摘要，匿名时为空>",
  "aud": "app.example.com",
  "sub": "1",
  "iat": 1794820000,
  "nbf": 1794819998,
  "exp": 1794820060,
  "authenticated": true,
  "username": "alice",
  "display_name": "Alice",
  "role": "user",
  "request_method": "GET",
  "request_uri_sha256": "<原始路径和查询字符串的 SHA-256 十六进制摘要>"
}
```

每个服务有独立的 256 位随机密钥，控制台显示为 64 字符文本。**把这 64 字符原样作为 UTF-8 HMAC 密钥使用，不要先做 hex 解码。** 后端固定只允许 `HS256`，验证签名、精确的 issuer/audience、exp/nbf/iat；可允许 3 秒时钟偏差。还应比对 `request_method` 以及原始路径和查询字符串的 SHA-256 摘要，防止把免登录路径的 token 用到其他路径。读取经过验证的 JWT claims 作为身份，不能只信任独立的身份请求头。

免登录路径的 token 仍然有效，但 `authenticated=false`、`sub=""`，用户名、显示名称和角色也为空。业务自己的受保护接口应要求 `authenticated=true`。用户密码和网关会话 Cookie 不会传给后端；独立的 `__Host-gateway_binding` Cookie 会被转发，SDK 必须比对它与 Token 中的摘要。后端自身的普通 Cookie、Authorization、请求路径、查询和正文保留。后端 Host 设置为后端地址，业务原域名在 `X-Forwarded-Host`。

后端验证不需要回调网关。使用缓存的独立密钥进行 HMAC 验证即可；token 有效期 60 秒，在这段时间内属于可重放的 bearer 凭据。建议远程后端使用 HTTPS。轮换密钥后新请求立即使用新密钥，后端需同步更新；若还接受旧密钥，旧 token 最长剩余 60 秒有效期。HS256 采用对称密钥，因此持有某服务密钥的后端也能为该服务签名，但不能签发其他服务的 token。

独立的 Python 3 / C++ SDK 位于 [`/data/code/gateway-sdk`](/data/code/gateway-sdk/README.md)。网关内部示例为 `examples/gateway_identity.h`。每次请求校验 `X-Gateway-Token` 和完整 `Cookie` 请求头，传入原始方法和未经解码/重写的 request-target（如 `/docs?a=1`）。请求头缺失、重复或过长时应拒绝。

```cpp
GatewayVerifier verifier(secret, "https://gateway.perfy576.com", "app.example.com");
auto identity = verifier.verify(request_token, request_method, original_request_uri, cookie_header);
// 在受保护的业务接口额外要求 identity.authenticated。
```

## 构建与运行

### 版本和在线校验

当前 Token 协议 v1（JWT 头 `gwv=1`、payload `ver=1`），Cookie 协议 v1（值的 `v1.` 前缀、payload `cookie_version=1`）。版本信息也被签名和 Cookie 摘要保护。未知版本不尝试猜测算法。

SDK 默认本地校验，支持配置 `auto` 在未知版本时回退到 `POST https://gateway.perfy576.com/verify`；`online` 每次查询网关。在线接口使用控制台钥匙弹窗里的独立校验凭据鉴权，按当前服务校验 Token、绑定 Cookie、请求信息、会话及权限。签名错误不会在 auto 模式下降级联网。网络失败一律拒绝。完整参数和示例见 SDK README。当前网关只支持 v1；未来增加协议时由网关维护新版本校验，旧 SDK 可在线回退。

在线校验凭据为 `HMAC-SHA256(service_secret, "gateway/verify-api/v1")` 的十六进制值，与签名密钥独立使用，不具备签发 JWT 的能力。密钥轮换时两者同步更新。本地校验不具备实时撤销能力，剩余有效期内仍可通过；需要即时撤销时使用 online。

```bash
sudo apt-get install build-essential git pkg-config libssl-dev libmariadb-dev nlohmann-json3-dev
make -j2
make test
```

原生 GNU Make 直接调用 C/C++ 编译器和 `ar`，包括 Workflow 依赖自身，不使用构建生成器。Workflow 固定为 `v0.11.11` 对应提交，jwt-cpp 固定为 `v0.7.1` 对应提交；首次构建从 GitHub 下载到 `.deps/`，校验提交后才使用。默认生成 `build/gateway`，`make test` 生成并运行安全测试，同时编译后端校验示例。

`make clean` 清除构建产物但保留下载的源码，之后可离线重建。支持 `BUILD_DIR`、`DEPS_DIR`、`CC`、`CXX`、`CPPFLAGS`、`CFLAGS`、`CXXFLAGS`、`LDFLAGS`、`LDLIBS`。编译选项变更后先执行 `make clean`。已有相同固定提交的本地源码时，可设置 `WORKFLOW_SRC=/path/to/workflow JWT_CPP_SRC=/path/to/jwt-cpp`，无需下载。Workflow 的原生编译规则针对 Linux。

`sudo make install` 安装网关二进制，支持 `PREFIX` 和 `DESTDIR`；不会自动覆盖环境配置、部署页面或重启运行中的服务。

运行文件：

- 程序：`/usr/local/bin/gateway`
- 页面资源：`/opt/gateway/web/`，本地静态资源，没有 CDN 运行依赖
- 环境配置：`/etc/gateway.env`，权限 0600；新部署可参考 `deploy/gateway.env.example`，不要将真实凭据加入 Git
- 初始密码：`/var/lib/gateway/initial-admin.txt`，权限 0600
- Caddy：`/etc/caddy/Caddyfile` 和 `/etc/caddy/gateway.caddy`
- 原 Caddy 配置备份：`/etc/caddy/Caddyfile.before-gateway-20261116`

```bash
sudo systemctl status gateway caddy
sudo journalctl -u gateway -f
sudo systemctl restart gateway
```

C++ 只监听 `127.0.0.1:19090`。公网不可暴露 `/internal/*`。Caddy 管理端口保持原配置，仅本机可达。配置变更通过管理 API 保存时立即更新内存；直接修改 MySQL 后需要重启网关。

该腾讯云 MySQL 实例当前 `have_ssl=DISABLED`。因此运行配置显式设置 `DB_TLS_REQUIRED=false`，数据库链路目前不加密。已为应用创建仅限 `gateway` 库的 DML 账号，应用不使用 root。启用腾讯云 SSL 后，配置 `DB_TLS_REQUIRED=true` 和 `DB_TLS_CA=/path/to/ca.pem`，会要求 TLS 并验证服务器证书；然后重启服务。

新实例先使用管理员客户端配置执行 `node tools/init-db.mjs /path/to/admin.cnf` 来创建数据库、表和专用账号。Node 仅用于初始化及测试，不参与线上运行。现有实例不要重复执行初始化以免生成无用账号；线上环境配置已经安装。

旧实例升级 AppID 字段时，由数据库管理员在 `gateway` 库执行 `migrations/002-service-appid.sql` 一次，再安装新版二进制。原服务会暂用 `app_<数据库ID>`，可在控制台编辑为自定义名称。本机实例已完成该迁移。

## 组件与验证

`web/components.js` 提供 `<gw-select>`、`<gw-option>` 和 `<gw-checkbox>` 组件。下拉框自绘，支持键盘选择、Esc、焦点和原生 FormData；复选框/开关以可访问的表单输入承载自定义外观。弹窗和字段通过 `showModal()`、`field()` 等复用。没有原生下拉菜单。

```bash
make -j2
make test
```

`tools/integration.mjs` 对实际 Caddy 和网关运行端到端测试，临时创建测试服务，检查多服务路由、独立密钥、登录、签名请求、回跳防重放、公开路径、身份头覆盖、JWT、SSE、WebSocket 和退出撤销。设置 `GATEWAY_TEST_RESTART=1` 可额外检查重启后的会话清空和 MySQL 配置保留，这会重启线上网关。最终 23 项检查已通过，临时服务和用户已清理。

`tools/app-login-integration.mjs` 验证自定义 AppID、Secret 轮换、两套 SDK 的接口登录、错误响应、一次性消费、服务隔离、权限和限流。与其他线上联调脚本顺序运行，避免测试账号的退出或限流互相干扰。

`tools/browser-check.mjs` 使用 Playwright 检查桌面/手机页面、管理操作和自定义控件；`tools/business-browser-check.mjs` 检查业务登录页的只读目标及真实浏览器跨域回跳。后者为虚拟测试域名启动本地 TLS relay，不改变生产 DNS。两组浏览器检查均已通过。测试需要本机初始管理员凭据副本 `.secrets/initial-admin.txt`，并会产生测试审计记录；页面截图和测试结果在 `artifacts/`。`PLAYWRIGHT_MODULE`、`CHROMIUM_PATH` 可指定测试工具路径。

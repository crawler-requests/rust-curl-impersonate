# rust-curl-impersonate

用 Rust 重写 [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate)。

curl-impersonate 是打在 curl 8.23.0 上的一组补丁，加上一份改过的 BoringSSL。指纹能生效是因为 BoringSSL 那部分：rustls 不暴露 cipher 顺序、扩展顺序、GREASE、ECH、ALPS、delegated credentials 和证书压缩。本仓库把传输层放在 [`wreq`](https://crates.io/crates/wreq) 上，它链接 BoringSSL 并给出这些控制项，然后在上面重写 curl 那一层：选择浏览器预设、套用 TLS、HTTP/2 与 HTTP/3 参数、发送请求。

`lib/impersonate.c` 的 48 个预设全部可用，包括 wreq-util 尚未收录的 Chrome 150–152、Firefox 153–155、Safari 260/270、OkHttp 和 Tor。

## 用法

```rust
use rust_curl_impersonate::{Client, Profile};

let profile = Profile::find("chrome150").expect("known target");
let client = Client::new(profile)?;
let response = client.get("https://example.com").send().await?;
println!("{}", response.status());
```

`Profile::find` 接受 `profile::TARGETS` 里的任何一个名字。`Client::get` 走 HTTP/2。带 QUIC 配置的预设用 `Client::http3_get` 发送，`Client::http3_endpoint` 是这条发送路径绑定的端点：HTTP/3 SETTINGS、传输参数、HTTP/3 请求头、连接 ID 长度，以及初始包号策略（Chrome 145/146/150 为 1，Firefox 147 为 Neqo 的 1..=1024 分布）。协商到 HTTP/3 之后，`Client::headers_after_negotiation` 使用该预设单独的 HTTP/3 默认头；回退时仍用普通默认头。Firefox 153、154、155 没有单独的 HTTP/3 指纹，调用方要求只走 HTTP/3 时会失败。

代理用 `ClientBuilder::proxy_url`，接受 `http://`、`https://` 和 `socks5://`。HTTP/3 走 `socks5://` 或 `socks5h://` 时改用 UDP ASSOCIATE（命令字节 `0x03`）。源站 DNS 交给 HTTP 代理或 SOCKS4a/SOCKS5h 时，客户端不会再对源站做一次直连的 HTTPS DNS 记录查询。`ClientBuilder::proxy_credential_no_reuse` 让后一次不同的代理凭据不能复用前一次的代理连接或 TLS 会话。

`Client::websocket_deflate` 在握手里带上 `permessage-deflate; client_max_window_bits`。对端接受后，`WebSocketUpgrade::accepted_codec` 压缩文本和二进制负载，再解压回原来的字节；控制帧保持未压缩。deflate 与 raw 模式同时打开是参数错误。`Client::try_websocket_deflate` 在没有链接 zlib 时返回 `WsError::NotBuilt`，并且不发出这个扩展。`ClientBuilder::ws_header`、`ws_header_order`、`ws_disable_ticket` 和 `ws_cert_compression` 只改 WebSocket 这一路的头和 TLS。

每个预设按 `lib/impersonate.c` 的顺序发送默认请求头。调用方同名头替换默认头，空值抑制该头，其余默认头保留。`Client::multipart` 使用预设的 `form_boundary`：WebKit 是 `------WebKitFormBoundary` 加 16 位字母数字，Firefox 是 `------geckoformboundary` 加 32 位十六进制。`okhttp4_android` 没有设置 `form_boundary`，`multipart` 返回 `None`。`ClientBuilder::form_boundary` 可改成 `webkit` 或 `firefox`。`Client::request_cookies` 与 `Client::request_cookies_for` 在 HTTP/1.1 发送一条 `Cookie` 头，在 HTTP/2 和 HTTP/3 按 cookie 拆开；当前 48 个预设都打开了 `split_cookies`。HTTP/2 伪头顺序只在预设写了 `http2_pseudo_headers_order` 时套用，Chrome 150 没有这项，不会补一个顺序。

`Client::cookie_changes` 的每一行是 `SET` 或 `DELETE`、一个制表符、然后一条 Netscape cookie。`Client::redirect_history` 的每一行是状态码、一个制表符、然后返回该状态的请求 URL，不含最终响应。`ClientBuilder::follow_safe` 会跟随重定向，但解析到的地址若是环回、私网或链路本地就拒绝这次连接；初始 URL 不受这道过滤。

不改 `src/profile/generated.rs` 也能覆盖预设里的 TLS、HTTP/2、HTTP/3 和 QUIC 字段，未设置的字段保持未设置。`Client::impersonate` 接受 `name[:yes|no]`，`yes` 安装默认头，`no` 不安装。`Client::impersonate_choice` 里显式目标优先于 `CURL_IMPERSONATE`。`Profile::register` 用一个新名字登记已有预设的线路设置，48 个内置目标仍然都能选到。`Client::prepared` 同时带着未改的字段和覆盖项。

`tools/gen_profiles.py` 从 `patches/curl.patch` 里 `impersonations[]` 的新增行解析预设。`split_cookies` 和 `form_boundary` 由 `src/profile/behavior.rs` 套用，不写进生成文件。

## 内置客户端指纹库

`fingerprint` 模块把真实客户端的抓包做成数据记录。161 条抓包记录配 33 个别名，覆盖 Go、Python（`requests`/`urllib`/`aiohttp`/`httpx`/`http.client`）、libcurl + OpenSSL、JDK `HttpClient`/`HttpsURLConnection`、Node.js（`https`/`http2`/`fetch`）、Bun、Deno、PHP（curl/stream 流）、Ruby `Net::HTTP`、GNU Wget（GnuTLS）、Perl LWP、OpenSSL `s_client`、Erlang/OTP `ssl`、Dart `dart:io`、.NET `HttpClient`、Rust reqwest + rustls、真实浏览器进程实测的 Chromium 156/157、Chrome for Testing 158/159 与 Firefox 158–162（stable/candidate/beta/nightly），来自 `bogdanfinn/tls-client` ClientHello 定义并实测抓包的 Chrome 103–152、Firefox 102–148、Safari 15–26（macOS/iOS/iPad）、Cloudflare 自定义 profile、Brave、Opera、Android 应用/OkHttp（Android 7–13、Mesh、ConfirmedAndroid、Nike、Zalando）和 iOS 应用（Confirmed、MMS、Mesh、Nike、Zalando），来自 `refraction-networking/utls` 的旧版 Chrome 58–133、Firefox 55–120、Safari 16/iOS 11–14、Edge 85/106、360 浏览器 7.5/11.0、QQ 浏览器 11.1 和 Android 11 OkHttp，以及用官方 Docker 镜像抓到的多版本运行时（Go 1.20–1.26、Node 24、PHP 7.4/8.1/8.2、Python 3.8/3.9/3.11、Java 8/11/17、.NET 8、curl 7.88.1/8.10.1、Ruby 3.3、Deno 2.9、Dart 3.13、Erlang OTP 27、OpenSSL s_client 1.1.1/3.1/3.3、Debian wget 1.21.3）：

```rust
let client = Client::new(Profile::find("go1.26")?)?;   // 或 "golang"
let client = Client::new(Profile::find("python")?)?;    // 即 python3.12_requests
let client = Client::new(Profile::find("chrome")?)?;    // 即 chromium156
let client = Client::new(Profile::find("firefox")?)?;   // 即 firefox158
let client = Client::new(Profile::find("ios")?)?;       // 即 ios_safari26
let client = Client::new(Profile::find("android")?)?;   // 即 android_okhttp13
```

### 指纹库是可加载的：Provider 机制

记录不是一团写死的 `include_str!`，`src/fingerprint/provider.rs` 把它们做成可插拔的 provider：

```rust
use rust_curl_impersonate::fingerprint::{register_provider, JsonProvider};

// 一份 JSON（或 from_path() 指向文件，每次 refresh 重读）就是一套新记录
let json = r#"[{"name":"acme_client","tls":{"ciphers":"TLS_AES_128_GCM_SHA256"}}]"#;
register_provider(JsonProvider::new("acme", json)).unwrap();
let profile = Profile::find("acme_client").expect("no install step needed");
```

- `FingerprintProvider`：`id` / `description` / `priority` / `load() -> Vec<Fingerprint>`，对象安全，外部 crate 也能实现。
- 内置实现：`BuiltinProvider`（本 crate 的库，id `builtin`，不可卸载）、`JsonProvider`（内存 JSON 或文件）、`DirProvider`（目录下全部 `*.json`）、`FnProvider`（闭包，每次 load 都调用）、`RemoteProvider`（从 URL 拉取云端指纹库，见下）。
- `register_provider` / `register_provider_with_priority` / `unregister_provider` / `refresh_providers` / `providers()` / `provider_of(name)`。
- 优先级 `PRIORITY_BUILTIN` (0) < `PRIORITY_CLOUD` (50) < `PRIORITY_USER` (100)：名字冲突时高优先级胜出，同优先级后注册者胜出。于是应用可以在运行时覆盖内置记录（打补丁、接付费记录集），而不必等 crate 发版；被覆盖的名字仍保持原位置，内置记录顺序不变。
- 注册前整体校验：provider 内重名、空名、保留/重复 id、`extends` 指向自身或无法解析的目标都会让整个 provider 回滚，不会留下半套记录。非别名记录的 TLS/HTTP/3 输入在注册时就构建，坏文档当场被拒。`Profile::find` 对 `extends` 链有深度上限，别名环也只会解析失败、不会死循环。
- `load()` 在注册表锁之外运行（`register_provider` 与 `refresh_providers` 都如此）：一个阻塞的 provider（比如网络拉取）不会卡住其它线程上的 `find`/`providers()`。provider 的实现因此不得调用注册表函数。
- `builtin()` 仍是嵌入库本身；`records()` 是合并视图；`find`/`names`/`families`/`by_family` 都读合并视图。`load_json`/`load_json_file`/`to_json` 语义不变。
- 一条记录就能表达**完整**浏览器 profile：TLS + HTTP/2 + headers + HTTP/3 + multipart 边界 + cookie 拆分全部是记录字段（`http3` / `form_boundary` / `split_cookies`），不需要 `extends` 指向预置。`ProfileSpec` 的 `http3_*` 构建器与记录的 `http3` 块是同一套生成逻辑；`behavior.rs` 的 48 目标行为表退为兜底。

#### 云端 Provider：把付费/扩展指纹库挂进来

`RemoteProvider` 就是预留的「云端 Provider」接缝——给它一个按库 schema 返回 JSON 的 URL，注册后云端记录和内置记录一样直接走 `Profile::find`，不需要 install、不需要等发版：

```rust
use rust_curl_impersonate::fingerprint::provider::{PRIORITY_CLOUD, RemoteProvider};
use rust_curl_impersonate::fingerprint::{register_provider, refresh_providers};

let provider = RemoteProvider::new("cloud-acme", "https://fingerprints.acme.example/v2/library")
    .with_description("premium records from acme")   // providers() 里展示
    .with_priority(PRIORITY_CLOUD)                   // 默认就是 50，覆盖内置、让位于用户本地
    .with_bearer_token(secret)                       // Authorization: Bearer <token>
    .with_header("X-Subscription", sub_id)           // 自定义订阅头
    .with_profile("chrome150")                       // 下载本身也伪装成浏览器（默认即是）
    .with_timeout(Duration::from_secs(10));
register_provider(provider).unwrap();                // 注册时完成首次拉取；失败即回滚

let premium = Profile::find("cloud_premium").unwrap(); // 云端专有记录立即可解析
refresh_providers().unwrap();                        // 带 If-None-Match 重验证
```

首次 `load` 会缓存响应的 `ETag`，`refresh_providers` 重拉时带上 `If-None-Match`：服务端回 `304 Not Modified` 就返回缓存记录，库不会被一次刷新清空。拉取走本 crate 自己的 `Client`（同步上下文里的私有 tokio runtime），Bearer token、自定义头、伪装 profile 都挂在同一个请求上。

仓库里带一套可端到端跑的通路：`tools/cloud_api.py` 是模拟云端服务的 mock（ETag + 304 + 可选 Bearer），`goal-evidence/cloud-library.json` 是一份示例云端库，`examples/cloud_provider.rs` 演示完整对接——mock 日志里能看到第一次 `-> 200`、刷新 `-> 304` 两个往返。示例库里的 `cloud_chrome_full` 是一条不依赖任何预置的完整 profile 记录（含 HTTP/3 全参数、`form_boundary`、`split_cookies`），演示「云端提供整份 profile」而不只是补丁。真实后端只需按同一 schema 提供文档并正确回 ETag。

48 个 curl-impersonate 预置本身也在这个机制的可覆盖范围内：一条同名 `chrome150` 的 provider 记录会整体替换预置的 wire/HTTP/3/behavior（`tests/providers.rs` 的 `a_provider_record_can_override_a_builtin_preset` 验证），卸载后恢复 generated.rs 原定义——所以 `generated.rs` 不再是唯一权威，而是"默认值"。

**Provider 协议**（`docs/provider-protocol.md`）把整份扩展契约写成规范：`FingerprintProvider` 的四个方法、优先级与遮蔽规则、`load()` 的生命周期保证（锁外运行、可重复调用、不得改注册表）、一条记录能表达的完整字段表，以及三种数据源的接入方式——内嵌文件（`include_str!` / `from_path` / `DirProvider`）、远端加载（`RemoteProvider` + ETag/304 服务端协议）、你完全自定义的源（实现 trait 即可，见 `examples/custom_provider.rs` 的手写实现）。"只要实现协议就能扩展"是这套机制的设计目标。数据/指纹 Provider 化的覆盖度盘点见 `goal-evidence/provider-coverage.md`。

Chromium 156/157 与 Firefox 158 记录来自当前机器上的真实浏览器进程，版本比 curl-impersonate 的 48 个预置（Chrome 150–152、Firefox 153–155）更新；GREASE、ALPS（17613）、ECH GREASE、证书压缩、`record_size_limit`、delegated credentials 都按抓包写入。Chromium 每次连接都会重排扩展列表，记录里的 `extension_order` 只是抓包得到的集合，`permute_extensions` 打开后由 BoringSSL 逐次随机排列；Firefox 的顺序固定，按原样发送。

更高版本同样来自真实浏览器进程，不是手写或改版本号：Chrome 157 取自本机 Snap Chromium，Chrome 158/159 取自 Google 官方的 **Chrome for Testing**（Beta/Dev 通道构建），Firefox 159–162 取自 Mozilla 官方 Snap 的 stable/candidate/beta/edge 通道（159.0.1 / 160.0 / 161.0b1 / 162.0a1）。每个版本都跑一次真实请求，从回显服务取回浏览器实际发出的 ClientHello。`tools/compare_echo.py` 对每条新记录做线上对比：Firefox 159–162 的 TLS 结构与 JA4 与抓包完全一致；Chrome 157/158/159 的差异只有 BoringSSL 发不出的扩展（4832、51764）、pre_shared_key（BoringSSL 仅在提供缓存 ticket 时才发）和 ML-DSA 签名算法，全部写进 `deviations`（证据 `goal-evidence/real-versions-echo.txt`）。

整库可溯源：每条记录的 `source` 都指向产生它的那份原始回显（如 `tls.peet.ws capture, tools/capture/raw/chromium157.json`），`tools/gen_fingerprints.py` 只读 `tools/capture/raw/` 下的抓包，重跑即可得到同一份库。161 条抓包记录逐条对应到一个存在的原始文件，33 个别名全部解析到抓包记录或 curl-impersonate 预置，没有任何 simulated、手写或改版本号的记录。逐条审计见 `goal-evidence/real-provenance.txt`。

同一语言的不同版本会发出不同的 ClientHello，光靠本机装的版本覆盖不到。`tools/capture/docker_capture.sh` 用官方镜像补齐：Go 1.19–1.25（1.26 取自本机）、Node 18/20/24（OpenSSL 3.5 的 X25519MLKEM768 + ML-DSA）、Python 3.8/3.9/3.10/3.11/3.13、Java 8 `HttpsURLConnection`（没有 `java.net.http`）与 Java 11/17 两种栈、curl 7.88.1（OpenSSL 1.1.1）与 8.10.1、OpenSSL `s_client` 1.1.1w/3.1/3.3、PHP 7.4/8.1/8.2 的 stream 流、Ruby 3.3 `Net::HTTP`、Deno（rustls）、Dart `dart:io`、Erlang/OTP 27 `ssl`、.NET 8 `HttpClient`（HTTP/1.1 与 HTTP/2 各一条）、Debian bookworm 的 GnuTLS wget。镜像里跑的是上游运行时本身，抓到的就是生产服务端会看到的 ClientHello；`Capture8.java` 是 Java 8 专用抓包程序，状态行写 stderr 以免混进 JSON，`dotnet_capture.cs` 用显式 `VersionPolicy` 请求 h2 或 h1。

`utls_` 前缀的 34 条记录来自 `refraction-networking/utls` 内置的 `ClientHelloID`，补齐了 tls-client 没有的旧版浏览器和国产浏览器：Chrome 58/62/70/72/83/87/96/100/102/106（含 shuffle 变体）/115 PQ/120/120 PQ/131/133、Firefox 55/56/63/65/99/102/105/120、Safari 16、iOS 11–14、Edge 85/106、360 浏览器 7.5/11.0、QQ 浏览器 11.1、Android 11 OkHttp。uTLS 只负责 TLS 握手，HTTP/2 栈由调用方决定，所以这些记录统一走 HTTP/1.1、只描述 ClientHello，ALPN 也只广告 `http/1.1`；`deviations` 里明确写了这一点。非 h2 的 ALPN 让它们和抓包保持同一形状，不会伪装成浏览器的完整 h2 列表。所有名字直接走 `Profile::find`。

`tlsclient_` 前缀的 52 条记录覆盖 tls-client 其余全部非 PSK profile：Chrome 103–152、Firefox 102–148、Safari 15.6/16（macOS）与 iOS 15.5–18、iPad 15.6、Opera 89/90、Brave 146、Cloudflare 自定义 profile，以及 MMS/Mesh/Nike/Zalando 的 iOS 应用。加上此前不带前缀的 Confirmed/Android/OkHttp/iOS/Opera 记录，tls-client 来源共 69 条。每条都按对应版本设置浏览器 UA 或 `CFNetwork`/`okhttp` 请求头，不共用相邻版本的默认头；Chrome 133 的 ALPN 里含 `h3`，`AlpnProtocol::HTTP3` 原样发送。所有名字都直接走 `Profile::find`，不需要安装步骤。

每条记录包含 TLS ClientHello 输入（cipher 顺序、曲线、签名算法、扩展顺序、key share、ALPN、TLS 版本、GREASE/ECH/ALPS/证书压缩等）、HTTP/2 SETTINGS/伪头顺序/连接窗口、默认请求头和是否只能走 HTTP/1.1。`Profile::family()`、`Profile::platform()`、`Profile::fidelity()`、`Profile::deviation_note()` 返回记录描述的信息；`fingerprint::find`、`names`、`families`、`by_family` 用于枚举库。

| 记录 | 客户端 | fidelity |
|---|---|---|
| `go1.26` / `go1.26_http1` | Go net/http | close |
| `python3.12_requests` / `_urllib` / `_aiohttp` / `_httpx` / `_httpclient` | Python 3.12 | partial |
| `curl8.5_h2` / `curl8.5_http1` | libcurl + OpenSSL 8.5 | partial |
| `java21_httpclient` / `java21_urlconn` | JDK 21 | partial |
| `node22_https` / `node22_http2` / `node22_fetch` | Node.js 22 | partial |
| `bun1.3.14` | Bun fetch（BoringSSL） | exact |
| `php8.3_curl` / `php8.3_streams` | PHP 8.3（libcurl / GnuTLS） | partial |
| `wget1.21.4` | GNU Wget + GnuTLS | partial |
| `perl5_lwp` | Perl LWP::UserAgent | partial |
| `openssl3_sclient` | OpenSSL 3.0 s_client | partial |
| `rust_reqwest_rustls` | reqwest + rustls | close |
| `chromium156` | Chromium 156（headless） | close |
| `firefox158` | Firefox 158（headless） | exact |
| `android_confirmed` / `android_confirmed2` | Android 应用（TLS 1.2，tls-client） | exact |
| `android_mesh` / `android_mesh1` | Mesh Android（HTTP/2 与 HTTP/1.1） | exact |
| `android_okhttp7` | OkHttp 4 / Android 7（NIST 曲线） | close |
| `android_okhttp8` / `_okhttp9` / `_okhttp10` / `_okhttp11` / `_okhttp12` / `_okhttp13` | OkHttp 4 / Android 8–13 | exact |
| `android_nike` | Nike Android 应用（只 GREASE key share） | close |
| `android_zalando` | Zalando Android 应用（带 SCT 扩展） | exact |
| `ios_confirmed` | iOS 应用（tls-client） | exact |
| `ios_safari18_5` / `ios_safari26` | Safari on iOS（tls-client） | exact |
| `opera91` | Opera 91（tls-client） | exact |
| `tlsclient_chrome103` … `_chrome152` | Chrome 103–152（tls-client，19 条） | exact 为主 |
| `tlsclient_firefox102` … `_firefox148` | Firefox 102–148（tls-client，14 条） | exact 为主 |
| `tlsclient_safari15_6_1` / `_safari16` | Safari 15.6.1/16（macOS） | exact |
| `tlsclient_ios_safari15_5` … `_18` | Safari on iOS 15.5–18 | exact |
| `tlsclient_ios_mms/mms2/mms3`、`_mesh`、`_nike`、`_zalando` | iOS 应用（tls-client） | exact |
| `tlsclient_opera89/90`、`_brave146`、`_cloudflare` | Opera 89/90、Brave 146、Cloudflare | exact / partial |
| `utls_chrome58` … `_chrome133` | Chrome 58–133（uTLS，15 条，HTTP/1.1） | exact 为主 |
| `utls_firefox55` … `_firefox120` | Firefox 55–120（uTLS，8 条，HTTP/1.1） | exact |
| `utls_safari16` / `_ios11` … `_ios14` | Safari 16、Safari on iOS 11–14（uTLS，HTTP/1.1） | exact / close |
| `utls_edge85/106`、`utls_360_7_5/11_0`、`utls_qq11_1`、`utls_android11okhttp` | Edge、360、QQ、Android 11 OkHttp（uTLS，HTTP/1.1） | exact / partial |
| `go1.20` … `go1.24` | Go net/http 1.20–1.24（Docker） | close |
| `node24_https` / `node24_http2` | Node.js 24 + OpenSSL 3.5（18/20/22 的 ClientHello 相同，由 Node 22 代表） | partial |
| `python3.8_urllib` / `_3.9` / `_3.11` | Python urllib（Docker；3.8 是 OpenSSL 1.1.1） | partial |
| `java8_urlconn` / `java11_httpclient` / `java11_urlconn` / `java17_urlconn` | Java 8/11/17（Temurin） | partial |
| `curl7.88.1_h2` / `_http1`、`curl8.10.1_h2` / `_http1` | libcurl + OpenSSL 1.1.1 / 3.x | partial |
| `openssl1.1_sclient` / `openssl3.3_sclient` | OpenSSL s_client 1.1.1w / 3.3.7 | partial |
| `ruby3.3_nethttp` | Ruby 3.3 Net::HTTP（OpenSSL 3.5，HTTP/1.1） | partial |
| `deno_fetch` | Deno 2.9 fetch（rustls，HTTP/2） | close |
| `dart_httpclient` | Dart 3.13 dart:io（自带 BoringSSL，HTTP/1.1） | exact |
| `erlang_ssl` | Erlang/OTP 27 ssl + httpc（HTTP/1.1） | partial |
| `dotnet8_http1` / `dotnet8_http2` | .NET 8 HttpClient（SocketsHttpHandler + OpenSSL） | partial |
| `wget1.21_bookworm` / `php8.1_streams` | Debian GnuTLS wget 1.21.3、PHP 8.1 streams | partial |

别名包括 `golang`、`python`、`httpx`、`curl`、`java`、`node`、`bun`、`php`、`wget`、`perl`、`rust`、`openssl`、`ruby`、`deno`、`dart`、`erlang`、`dotnet`、`chrome`、`firefox`、`android`、`android7`、`android8`、`android9`、`android10`、`android11`、`android12`、`nike`、`zalando`、`ios`、`opera`、`chrome_android`、`safari_ios`、`okhttp_android`。

外部记录用同一套 JSON schema，可读文件或字符串，支持一条记录、数组或 `{"fingerprints":[...]}`，`extends` 表示复用另一个名字的线路设置：

```rust
let profiles = rust_curl_impersonate::fingerprint::load_json_file("my-clients.json")?;
// 或 fingerprint::load_json(text)?;  fingerprint::to_json(&records)?;
```

```json
{
  "name": "my-client",
  "family": "custom",
  "client": "My HTTP client",
  "platform": "linux",
  "fidelity": "close",
  "tls": {
    "ciphers": "TLS_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "curves": "X25519:P-256",
    "extension_order": "0-10-16-43-51",
    "alpn": ["h2", "http/1.1"],
    "cert_compression": "brotli",
    "record_size_limit": 16385,
    "delegated_credentials": "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384"
  },
  "http2": { "settings": "2:0;4:4194304", "pseudo_order": "a,m,p,s", "window_update": 1048576 },
  "headers": [["user-agent", "my-client/1.0"]]
}
```

记录不能和 48 个内置目标或已安装名字重名；`validate()` 会在不联网的情况下检查字段，非法 ALPN、TLS 版本、扩展 id、key share 都会报错。别名只改元数据，线路设置始终来自被指向的记录。抓包生成脚本是 `tools/gen_fingerprints.py`（输入 `tools/capture/raw/*.json`），生成 `src/fingerprint/builtin.json`；`tools/capture/capture.sh` 逐客户端重新抓包，浏览器分别由 `chromium_capture.py`（headless `--dump-dom`，可传第二个参数指定任意官方构建如 Chrome for Testing）和 `firefox_capture.py`（geckodriver + JSON 查看器的 Raw Data 标签）产生，全部 tls-client 记录（桌面浏览器、移动端、Opera/Brave/Cloudflare）由 `tlsclient_capture/` 里的小 Go 程序按 `tls-client` 的 ClientHello 定义发出，uTLS 记录由 `utls_capture/` 用 `UTLSIdToSpec` 拆出 spec 后经 `HelloCustom` 发出。 本机没有的运行时版本由 `docker_capture.sh` 在官方镜像里跑；它和 `capture.sh` 分开，避免每次全量抓包都拉镜像。`tools/compare_echo.py` 对比回显与抓包，`tools/check_subset.py` 校验可发送子集。httpx 的 h2 抓包需要 `h2`，用 `CAPTURE_PYTHON` 指向带该模块的解释器。

### 抓包复现结果

`cargo run --example echo <记录名>` 对 `tls.peet.ws` 实测 154 条抓包记录：HTTP/2 SETTINGS、WINDOW_UPDATE、伪头顺序、普通头顺序、HTTP/1.1 请求头、ALPN、cipher/曲线/签名算法的相对顺序、扩展集合、key share 全部与抓包一致（Chromium 的扩展顺序每次连接随机重排，其余记录按抓包顺序）；剩余差异只有 BoringSSL 发不出的字段，并逐条写进记录的 `deviations`。新增的 Chromium 157 / Chrome 158 / Chrome 159 与 Firefox 159–162 同样逐条实测，结果见 `goal-evidence/real-versions-echo.txt`：

- BoringSSL 总是把 TLS 1.3 cipher 排在 TLS 1.2 前面（Go 的抓包相反）；
- 不支持的 cipher suite、X448/ffdhe4096+ 曲线、`rsa_pss_pss_*`/DSA/`ecdsa_sha224` 等签名算法、`signature_algorithms_cert`/`status_request_v2`/`encrypt_then_mac` 不会发送；
- Chrome 156 的 `mldsa44`/`mldsa65`/`mldsa87` 以及 tls.peet.ws 未命名的扩展 51764 发不出去；BoringSSL 的 GREASE 覆盖 cipher、曲线、版本、key share 和扩展，但不覆盖 signature_algorithms；
- Go/JDK 的抓包没有 padding (21)，而 BoringSSL 在 ClientHello 长度 256–511 字节时会自动追加；
- Node 的 `:authority` 带默认 `:443`，传输层省略默认端口；
- Node HTTP/2 的空 SETTINGS 帧无法发送，改用 `INITIAL_WINDOW_SIZE=65535` 近似；
- Firefox 102–123 的抓包在 HEADERS 前有 6 个 RFC 7540 PRIORITY 帧，传输层不发这些帧；
- Cloudflare 自定义 profile 是 TLS 1.2 的 5 cipher/8 扩展组合，BoringSSL 只能发出其中 4 个 cipher 和大部分扩展。

Chromium 156 和 Firefox 158 实测的 JA4 分别是 `t13d1516h2_8daaf6152771_d8a2da3f94cd` 和 `t13d1517h2_8daaf6152771_3cbfd9057e0d`；Firefox 的扩展顺序逐项一致，Chromium 的扩展集合一致且每次连接重新排列，两者的 cipher/曲线/签名算法、key share、HTTP/2 SETTINGS、伪头顺序与请求头顺序都与记录一致。Bun 的 JA4 是 `t13d1714h1_5b57614c22b0_43ade6aba3df`，HTTP/1.1 的字段全部在 BoringSSL 能表达的范围内。

全库实测汇总：154 条抓包记录里 90 条的 cipher、曲线、签名算法、扩展集合与顺序、ALPN 和 JA4 与抓包完全一致，94 条 JA4 相同；`tools/check_subset.py` 对 154/154 条确认「BoringSSL 能发的那部分字段、顺序与抓包完全一致」——OpenSSL/GnuTLS 系的 X448、ffdhe4096+、brainpool、ML-DSA、CCM、DHE-DSS 和 `encrypt_then_mac` 发不出，属能力边界而不是映射错误。新增 34 条 uTLS 与 28 条 Docker 记录的子集检查同样全部通过（34/34、28/28）。逐条表格由 `tools/library_report.py` 重新生成（`goal-evidence/full-library.txt`）。新增 7 条最新版本记录（Chromium 157、Chrome 158/159、Firefox 159–162）的线上验证见 `goal-evidence/real-versions-echo.txt`。

新增的 34 条 `utls_` 记录全部实测：23 条的扩展集合/顺序、cipher、曲线、签名算法和 JA4 与抓包逐项相同（`utls_chrome106shuffle` 是随机重排，集合相同；`utls_chrome120` 的 padding 21 随 ClientHello 长度变化，因此偶尔出现或消失）。其余差异都在 `deviations` 里：Chrome 58/62/70 与 360 11.0 的 BoringSSL ChannelID 扩展 30032 发不出；iOS 11/12 与 360 7.5 的 NPN（13172）发不出；360 7.5 还带旧 ChannelID 30031、RC4/DHE-DSS cipher 和 DSA 签名算法，且抓包没有 BoringSSL 必发的 extended_master_secret（23），记录为 `partial`；Chrome 115/120 PQ 的 X25519Kyber768 key share 发不出，记录为 `close`。

新增的 52 条 `tlsclient_` 记录中，48 条的实测 JA4 与抓包完全相同，cipher、扩展集合、HTTP/2 SETTINGS 和伪头顺序也逐项一致。4 条不同：`tlsclient_chrome146/150/152` 发出的扩展 51764 与 ML-DSA 签名算法 BoringSSL 不支持；`tlsclient_cloudflare` 的 TLS 1.2 cipher 与 `encrypt_then_mac` 扩展发不出，记录是 `partial`。`tlsclient_firefox102/104/105/106/108/110/117/120/123` 的 JA4 相同，但抓包带 6 个 PRIORITY 帧，实测没有，fidelity 因此是 `close`。

十七条移动端/Opera 记录里，十五条的实测 JA4 与抓包完全相同：`android_confirmed` `t12d129h2_d34a8e72043a_b39be8c56a14`、`android_mesh` `t13d1516h2_8daaf6152771_e5627efa2ab1`、`android_mesh1` `t12d149h1_c866b44c5a26_b39be8c56a14`（HTTP/1.1）、`android_okhttp8` `t12d129h2_d34a8e72043a_e08eabe7240f`、`android_okhttp9` `t12d129h2_d34a8e72043a_b39be8c56a14`、`android_okhttp10/11/12/13` `t13d1513h2_8daaf6152771_eca864cca44a`、`android_nike` `t13d1513h2_8daaf6152771_eca864cca44a`、`android_zalando` `t13d1514h2_8daaf6152771_43ade6aba3df`、`ios_confirmed` `t13d1314h2_f57a46bbacb6_14788d8d241b`、`ios_safari18_5` `t13d2014h2_a09f3c656075_e42f34c56612`、`ios_safari26` `t13d2013h2_a09f3c656075_7f0f34a4126d`、`opera91` `t13d1516h2_8daaf6152771_e5627efa2ab1`。cipher、扩展集合与顺序、HTTP/2 SETTINGS、伪头顺序和请求头顺序也逐项一致；`ios_safari18_5` 的 3DES 套件 BoringSSL 仍能发送。

剩余差异都在 `deviations` 里：`android_confirmed2` 的抓包含 padding 扩展（21），BoringSSL 只在 ClientHello 长 256–511 字节时自动追加，实测长度落在范围外，JA4 因此少一个扩展（`t12d129h2_d34a8e72043a_b39be8c56a14`，抓包是 `t12d1210h2_d34a8e72043a_f88f2b2eb673`）；`android_okhttp7` 的两个 SHA-224 签名算法 BoringSSL 发不出，JA4 的签名算法段不同，cipher、曲线、扩展和 SETTINGS 仍一致；`android_nike` 只 GREASE key share，而 BoringSSL 的 GREASE 开关会同时给 cipher、曲线、版本、key share 和扩展加 GREASE，JA4（忽略 GREASE）相同，但 JA3 的 cipher 列表比抓包多一个 GREASE 值。

传输层只有在记录本身带 `accept-encoding` 时才发这个头。抓包没有该头的客户端（curl、JDK `HttpClient`、Node `http2`、`HttpsURLConnection`、Node `https`）会关掉自动解压，避免 wreq 默认补一个 `accept-encoding`。ALPN 也按记录精确发送：没有 ALPN 的客户端不再被 HTTP/1.1 偏好补上 `http/1.1`，`h2` 客户端保留 `h2,http/1.1` 两项。

## 已验证

`cargo run --example echo <target>` 对 `https://tls.peet.ws/api/all` 发一次请求，服务器回显的握手与预设一致：

| 预设 | 回显核对 |
|---|---|
| `chrome150` | JA4 `t13d1515h2`，首个 cipher 为 GREASE，曲线 `X25519MLKEM768:X25519:P-256:P-384`，扩展 65037（ECH）与 17613（ALPS 新 codepoint），HTTP/2 SETTINGS `1:65536;2:0;4:6291456;6:262144`。该预设没有设置 HTTP/2 伪头顺序。UA Chrome/150.0.0.0 |
| `firefox133` | 扩展顺序 `0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27-65037` 逐项一致，含 delegated credentials (34)、record_size_limit (28)、compress_certificate (27)；曲线含 `X25519MLKEM768`、`P-521`、`ffdhe2048`、`ffdhe3072`；HTTP/2 SETTINGS `1:65536;2:0;4:131072;5:16384`，伪头 `m,p,a,s` |
| `safari180` | HTTP/2 SETTINGS `2:0;3:100;4:2097152;8:1;9:1`，含 `ENABLE_CONNECT_PROTOCOL` 与 `NO_RFC7540_PRIORITIES`，伪头 `m,s,a,p`，曲线 `X25519:P-256:P-384:P-521` |

## 传输层表达不了的字段

`profile::deviation` 按预设列出仍然发不出去的字段：

- **只有三个 ML-DSA 签名算法被丢掉。** Chrome 150 及更新的预设把 `mldsa44`、`mldsa65`、`mldsa87` 放在签名算法列表开头。BoringSSL 拒绝这三个名字，实际装上的算法列表里没有它们。除此之外的签名算法都会保留。code point 仍是草案，没有硬编码。

HTTP/3 由 `Client::http3_get` 发送。第一枚 Initial 的包号就是预设策略的结果：Chrome 145/146/150 为 1，Firefox 147 的 `-1` 落在 1..=1024。`15:AUTO` 的源连接 ID 与包头里的 Source Connection ID 是同一串字节。

## 构建

```bash
cargo test
cargo run --example echo chrome150
```

`wreq` 在编译期构建 BoringSSL，首次编译需要 C 编译器和 cmake，耗时几分钟。

## 与参考项目的覆盖对比

参考项目 [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate) 2.3.0 的 47 个浏览器 target 全部覆盖（本仓库的 `TARGETS` 有 48 个，多 `okhttp4_android`），10 个 HTTP/3 专用指纹一一对应，TLS/HTTP2/HTTP3 的可控字段均有对应方法。实质缺口只有真实 ECH（本仓库只能发 ECH grease）和 curl 的非 HTTP 协议族。参考项目的 curl 命令行、libcurl C ABI、预编译二进制与官方 Python/Node 绑定属于交付形态，不在本仓库内置。逐项矩阵见 [`docs/reference-coverage.md`](docs/reference-coverage.md)。

## 其他语言封装

仓库内的 `bindings/ffi` 把本 crate 暴露成 C ABI 共享库（`cdylib` + `rci.h`），Python/Node/Go/Java/C++ 都可以直接链接：

```bash
cargo build -p rust-curl-impersonate-ffi --release
python3 bindings/ffi/python/demo.py chrome150 https://tls.peet.ws/api/all
```

Python `ctypes` 实测返回 HTTP 200、`h2`、Chrome/150.0.0.0 的 UA 与 JA4。下游项目**不需要**配置任何 `[patch.crates-io]`：本 crate 直接依赖仓库内的 `vendor/wreq`、`vendor/quinn`、`vendor/quinn-proto`，用 path 或 git 依赖指向本仓库即可编译（已用独立消费者零配置实测）。每个 `v*` tag 由 GitHub Actions 构建 Linux（gnu/musl × x86_64/aarch64）、macOS（x86_64/arm64）、Windows（x86_64/arm64）与 Android arm64 的二进制并附 `SHA256SUMS`。构建与调用细节见 [`bindings/ffi/README.md`](bindings/ffi/README.md)。

## 发布与 CI

仓库自带两条 GitHub Actions 流程：

- **CI**（`.github/workflows/ci.yml`）：在 Linux 上跑 `cargo test --workspace`；另外新建一个只写 path 依赖、不写任何 `[patch.crates-io]` 的外部消费者并编译运行；再把 cdylib 加载进 Python，对一个本地 HTTP 服务做端到端冒烟。
- **Release**（`.github/workflows/release.yml`）：推送 `v*` tag（或手动触发）后按矩阵构建
  `x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`、`x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl`、
  `x86_64-apple-darwin`、`aarch64-apple-darwin`、`x86_64-pc-windows-msvc`、
  `aarch64-pc-windows-msvc`、`aarch64-linux-android` 的 C ABI 共享库与 `echo`
  冒烟程序，打成 `rust-curl-impersonate-ffi-<version>-<target>.tar.gz`（Windows 为
  `.zip`，内含 `lib/`、`include/rci.h`、`bin/echo`、LICENSE 与绑定 README），
  汇总 `SHA256SUMS` 后发布到 GitHub Release。9 个目标全部构建成功后才会发布；
  `v0.1.0` 的产物见 <https://github.com/crawler-requests/rust-curl-impersonate/releases/tag/v0.1.0>。

本地复现某个平台的产物：

```bash
cargo build --release -p rust-curl-impersonate --example echo --target <triple>
cargo build --release -p rust-curl-impersonate-ffi --target <triple>
python3 scripts/package_artifact.py --target <triple> --version 0.1.0 --out dist
```

BoringSSL 由 `btls-sys` 在编译期用 CMake 构建，因此每个目标都需要对应的 C/C++
工具链：Linux aarch64 用 `gcc/g++-aarch64-linux-gnu`，Linux musl 用 Zig
（`zig cc`/`zig c++`，并关闭 `crt-static`），Android 用 NDK，macOS/Windows 用
各自的原生工具链。

**下游怎么用**：Rust 项目直接 `rust-curl-impersonate = { path = "..." }` 或
`{ git = "https://github.com/crawler-requests/rust-curl-impersonate" }`，不需要
任何 patch 或额外 vendor 配置；其他语言直接下载对应平台的 release 压缩包，链接
`lib/` 里的共享库并 `#include "rci.h"`。crates.io 发布是另一回事：registry 不
接受 path 依赖，届时需要把 `vendor/` 下的修改上游化；GitHub Releases 的二进制
分发不受影响。

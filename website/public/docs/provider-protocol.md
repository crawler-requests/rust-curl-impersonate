# Provider 协议：扩展数据源的唯一入口

本仓库里凡是"描述客户端/浏览器该长什么样"的数据——TLS ClientHello、HTTP/2
SETTINGS、请求头、HTTP/3 参数、multipart 边界、cookie 拆分——都通过
**Provider 机制**供给。你不需要改本仓库的代码，只要实现下面这份协议，就能从
任何地方把数据接进来：内嵌在程序里的文件、远端指纹服务、你自己服务器上的库。

## 一句话协议

> 实现 `FingerprintProvider`，`load()` 返回一批 `Fingerprint`，注册进注册表，
> 名字立即可被 `Profile::find` 解析。

```rust
use rust_curl_impersonate::fingerprint::provider::{
    register_provider, FingerprintProvider,
};
use rust_curl_impersonate::fingerprint::Fingerprint;

/// 你的实现：从任何地方取数据（内嵌文件 / 远端 / 自己的服务器）。
#[derive(Debug)]
struct MyProvider;

impl FingerprintProvider for MyProvider {
    fn id(&self) -> &str { "my-provider" }            // 注册表内唯一
    fn description(&self) -> &str { "records from ..." }
    // priority() 默认 PRIORITY_USER(100)，可覆盖

    fn load(&self) -> Result<Vec<Fingerprint>, String> {
        // 1) 取数据（读文件、HTTP GET、查库……）
        // 2) 用 Fingerprint 的 serde 结构解析
        // 3) 返回
        unimplemented!()
    }
}

register_provider(MyProvider).unwrap();
let profile = rust_curl_impersonate::Profile::find("your_name").unwrap();
```

## 协议契约

`FingerprintProvider` 只有四个方法，其中 `id` 和 `load` 必须实现：

| 方法 | 说明 |
|---|---|
| `id()` | 注册表内唯一标识，显示在 `providers()` 里。`builtin` 被内置库占用。 |
| `description()` | 一句话说明数据来源，默认空串。 |
| `priority()` | 与其它 provider 的优先级。见下节。 |
| `load()` | 返回这批记录的完整列表。被调用两次：注册时一次，`refresh_providers()` 再一次。 |

**生命周期保证（实现前必读）：**

- `load()` 在**注册表锁之外**运行：注册与刷新都不会阻塞其它线程上的
  `find`/`providers()`。你的 `load()` 想跑多久跑多久，但**不得**调用任何注册表
  函数（`register_provider`/`unregister_provider`/`find`/`providers`/`refresh`）。
- `load()` 必须可安全地重复调用（每次 `refresh_providers` 都会再调一次）。
- `load()` 返回的每条记录，非别名记录（无 `extends`）会在注册时被当场构建成
  线上选项；名字为空、重名、`extends` 指向自身或未知 profile、TLS/HTTP/3 输入
  无法构建，都会让**整个 provider 注册失败并回滚**，不会留下半套记录。
- 你的 provider 对象必须 `Send + Sync + Debug`（trait 有这些约束），因为它被
  `Arc` 共享、可能被并发 refresh。
- 注册后记录立即生效；卸载用 `unregister_provider(id)`，名字随之消失（除非别的
  provider 或预设还提供）。

## 优先级与遮蔽

每个 provider 有 `priority`。名字冲突时，高优先级胜出；同优先级后注册者胜出：

```
PRIORITY_BUILTIN = 0   内置库（builtin.json，不可卸载）
PRIORITY_CLOUD   = 50  云端/远程库（RemoteProvider 默认）
PRIORITY_USER    = 100 你注册的任何 provider（默认）
```

因此你可以：

- **覆盖**内置库或 48 个 curl-impersonate 预设的同名记录（比如给 `go1.26`、
  甚至 `chrome150` 换 cipher 列表）——无需改 generated.rs。卸载后恢复原状。
- **打补丁**：同一名字，优先级高于内置的新记录进场，旧记录自动被遮蔽；
  `providers()` 里能看到 `overrides`。
- **扩展**：新名字直接可用，`Profile::find` 无需 install 步骤。

## 一条记录能表达什么

`Fingerprint` 是完整浏览器/客户端的描述，所有字段都是可选的：

```
name / extends          名字；extends 复用另一记录（别名）的线上字节
family/client/version/platform/source/fidelity/deviations
tls:   ciphers, curves, sigalgs, extension_order, key_shares, alpn,
       min/max_version, grease, permute_extensions, session_ticket,
       ocsp_stapling, signed_cert_timestamps, ech_grease, alps,
       new_alps_codepoint, renegotiation, psk_dhe_ke,
       preserve_tls13_cipher_list, cert_compression, record_size_limit,
       delegated_credentials
http2: settings, pseudo_order, window_update, initial_window_size, no_priority
headers / header_order / http1_only
form_boundary / split_cookies          multipart 边界与 cookie 拆分
http3: curves, settings, initial_packet_number, sigalgs, ciphers,
       transport_parameters, pseudo_order, extension_order, grease,
       session_ticket, permute_extensions, ech_grease,
       signed_cert_timestamps, new_alps, ocsp_stapling,
       delegated_credentials, record_size_limit, cert_compression,
       header_order, headers
```

JSON 里就是这些字段名（snake_case）。记录可以是 `{...}` 单个、`[...]` 列表、或
`{"fingerprints":[...]}` 包装。加载与序列化见 `fingerprint::parse_json` /
`to_json`。

`source` 是可选的来源标注，消费方可以拿它做显示或审计。本仓库的内置库全部来自
真实抓包（`tools/capture/` 各脚本产生，原始输出在 `tools/capture/raw/`），
`source` 是抓包方式与客户端版本的描述；`deviations` 逐条列出 BoringSSL
发不出、因而不在 wire 上的字段。

## 三种数据源，同一份协议

### 1. 内嵌文件（随程序分发，离线可用）

内置库 `BuiltinProvider` 就是这条路：`include_str!` 把文件编进二进制。你自己
想要一份打进二进制的库，有几种做法：

```rust
// 方案 A：注册时从磁盘读（文件单独分发，refresh 重读）
use rust_curl_impersonate::fingerprint::provider::JsonProvider;
register_provider(JsonProvider::from_path("acme", "data/library.json")).unwrap();

// 方案 B：整个目录都是库（每个 .json 一个文档）
use rust_curl_impersonate::fingerprint::provider::DirProvider;
register_provider(DirProvider::new("acme", "/etc/acme/fingerprints")).unwrap();

// 方案 C：把 JSON include 进代码，完全离线+不可改
const LIBRARY: &str = include_str!("../data/library.json");
register_provider(JsonProvider::new("acme", LIBRARY)).unwrap();
```

### 2. 远端加载（URL + JSON + ETag 重验证）

`RemoteProvider` 已经实现了整套 HTTP 协议：GET 一个 URL，解析库 schema 的
JSON，缓存响应 `ETag`，`refresh_providers()` 时带 `If-None-Match`——服务端回
`304` 就返回缓存，库不会被刷新清空。支持 Bearer token、自定义头、伪装下载
profile、超时：

```rust
use std::time::Duration;
use rust_curl_impersonate::fingerprint::provider::{RemoteProvider, PRIORITY_CLOUD};

let provider = RemoteProvider::new("cloud-acme", "https://api.acme.example/library")
    .with_priority(PRIORITY_CLOUD)
    .with_bearer_token(secret)
    .with_header("X-Lane", "premium")
    .with_profile("chrome150")          // 下载本身也伪装成浏览器
    .with_timeout(Duration::from_secs(10));
register_provider(provider).unwrap();
```

服务端协议（对你自己的服务器同样适用，仓库里的 mock
`tools/cloud_api.py` 是参考实现）：

```
GET /fingerprints.json
  → 200, ETag: "…", body = 库 JSON          首次拉取
  → 304, ETag: "…"（当请求带 If-None-Match: "…"）  重验证命中
  → 401（当协议要求 Bearer 且未带/带错）
```

### 3. 你自己的服务器 / 任意数据源（实现协议即可）

任何能让 `load()` 拿到数据的地方都是合法的 provider：Postgres、S3、公司内部
API、加密文件、动态生成的库…… 用 `FnProvider`（闭包）最省事：

```rust
use rust_curl_impersonate::fingerprint::provider::FnProvider;

register_provider(FnProvider::new("internal", || {
    let text = my_internal_fetch()?;   // 任何方式
    rust_curl_impersonate::fingerprint::parse_json(&text)
})).unwrap();
```

或者完全自定义（比如你的服务不回 JSON，而是自定义格式）：

```rust
#[derive(Debug)]
struct GrpcProvider { endpoint: String }

impl FingerprintProvider for GrpcProvider {
    fn id(&self) -> &str { "grpc" }
    fn load(&self) -> Result<Vec<Fingerprint>, String> {
        let records = my_grpc_client.list(&self.endpoint)?;   // 任意格式
        Ok(records)   // 转成 Vec<Fingerprint>
    }
}
```

协议就这么多。四个方法、一份 serde 结构、三次调用时机（注册/刷新），你的数据
源就接进了 `Profile::find`。写一个 provider 不依赖本仓库任何内部实现。

## 常见问题

- **`find` 返回 None？** 名字拼错、provider 没注册成功（看注册错误信息）、或
  名字被更高优先级的记录遮蔽。
- **`extends` 是什么？** 别名：`{"name":"my","extends":"chrome150"}` 表示"线上
  字节完全复用 chrome150，只改元数据"。别名记录不参与 TLS/HTTP3 构建校验，但
  `extends` 指向的名字必须最终可解析（含被其它 provider 提供的情况）。
- **能覆盖内置库的 `go1.26` 吗？** 能。高优先级同名记录自动遮蔽，卸载后恢复。
- **能覆盖 48 个预设（`chrome150` 等）吗？** 能，同一个机制。预设名是注册表
  里的普通名字，provider 记录同名即整体替换其 wire/HTTP3/behavior；卸载后
  恢复 generated.rs 的原始定义。
- **刷新失败会怎样？** `refresh_providers()` 返回所有失败 provider 的错误串，
  但成功的照常应用；失败的 provider 保留上一次成功加载的记录。
- **需要线程安全吗？** 是。`load()` 可能在任何线程被调用（远程 provider 的
  私有 runtime、refresh 线程）。返回的记录会被 `'static` 化，因此你的数据要么
  本身是 `'static`，要么在你的 provider 里自己管理生命周期。
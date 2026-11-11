# 与参考项目 curl-impersonate 的功能覆盖对比

参考对象：[lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate) 2.3.0
（基于 curl 8.23.0），README 列出的 47 个浏览器 target、TLS/HTTP2/HTTP3 指纹与
配套工具链。

结论先说：**指纹能力已经完整覆盖并超出；HTTP 客户端能力覆盖爬虫需要的部分；
参考项目的交付形态（curl CLI、libcurl C ABI、预编译二进制、官方 Python/Node
绑定）不是本仓库内置的，本轮补了 C ABI 共享库骨架，其余需要按第 4 节自己封装。**

## 1. 浏览器 target

| 项目 | 参考项目 | 本仓库 |
|---|---|---|
| target 数量 | README 表 47 个 | `TARGETS` 48 个 |
| 缺失 | — | 无（参考项目的 47 个全部存在） |
| 额外 | — | `okhttp4_android` |
| HTTP/3 专用指纹 | 10 个：chrome145/146/150/151/151_macos/152/152_macos、firefox147、safari270/270_ios | 同名 10 个函数 `http3_profile_*`，完全对应 |
| 指纹数据来源 | 浏览器实测签名库 | 48 个预置 + 161 条独立真实抓包（含 Chromium 157、Chrome 158/159、Firefox 159–162 等参考项目尚未收录的版本） |

## 2. 指纹字段

参考项目为了仿真浏览器，需要控制的每一类线上字节在本仓库都有对应的
`ClientBuilder` 方法或记录字段：

| 类别 | 参考项目能力 | 本仓库 |
|---|---|---|
| TLS cipher 顺序 | ✅ | `cipher_list()`、记录 `tls.ciphers` |
| 曲线 / key share | ✅ | `key_shares()`、`key_shares_limit()`、记录 `tls.curves` |
| 签名算法 | ✅ | `sigalgs()`、记录 `tls.sigalgs` |
| 扩展顺序 | ✅ | `extension_order()`、`permute_extensions()` |
| TLS GREASE 开关 | ✅ | `grease()` |
| ALPS（17513/17613） | ✅ | `enable_alps()`、`new_alps_codepoint()` |
| ECH | 支持配置真实 ECHConfig | **仅 ECH grease**（`ech_grease`）；传输层 wreq 没有封装 `SSL_set1_ech_config_list`，发不了真实 outer/inner ClientHello |
| 证书压缩 | ✅ | `cert_compression()` |
| session ticket / OCSP / SCT | ✅ | `session_ticket()`、`status_request()`、`signed_cert_timestamps()` |
| delegated credentials | ✅ | `delegated_credentials()` |
| record_size_limit | ✅ | `record_size_limit()` |
| 信任锚 / 证书校验 | ✅ | `trust_anchors()`、`key_usage_no_check()` |
| TLS 版本范围 | ✅ | 记录 `min_version`/`max_version` |
| HTTP/2 SETTINGS | ✅ | `http2_settings()`、`http2_initial_window_size()` |
| HTTP/2 WINDOW_UPDATE | ✅ | `http2_window_update()` |
| HTTP/2 伪头顺序 | ✅ | `http2_pseudo_order()` |
| HTTP/2 请求头顺序 | ✅ | `header_order()` |
| Akamai h2 指纹（优先级帧） | ✅ | `http2_no_priority()`、`stream_exclusive()`、记录 `priority_frames` |
| HTTP/3 SETTINGS | ✅ | `http3_settings()` |
| HTTP/3 伪头/头顺序 | ✅ | `http3_pseudo_order()`、`http3_header_order()` |
| QUIC 传输参数 / CID 长度 / 初始包号 | ✅ | `quic_transport_parameters()`、`quic_cid()`、`initial_packet_number()` |
| HTTP/3 曲线与签名算法 | ✅ | `http3_curves()`、`http3_sigalgs()` |

唯一实质缺口是**真实 ECH**：Chromium 119+ 在拿到 DNS HTTPS 记录里的 ECHConfig
后会发加密的 inner ClientHello；本仓库只能发 ECH grease。对没有配置 ECH 的站点，
两者的线上形状相同；对配置了 ECH 的站点，JA4 会不同。要补齐，需要在
`vendor/wreq` 暴露 BoringSSL 的 ECH config API，再把 ECHConfigList 传进来。

## 3. HTTP 客户端能力

参考项目是 curl 的补丁版，天然继承 curl 的全部协议（FTP、SMTP、TELNET 等）。
本仓库只做 HTTP 栈，覆盖爬虫需要的部分：

| 能力 | 状态 |
|---|---|
| HTTP/1.1 | ✅ |
| HTTP/2 | ✅ |
| HTTP/3（含 0-RTT 参数、QUIC 指纹） | ✅ |
| WebSocket（permessage-deflate） | ✅ |
| gzip / deflate / brotli / zstd | ✅ |
| cookie 存储、逐条 `Cookie` 头拆分 | ✅ |
| 重定向与重定向历史 | ✅ |
| 代理、SOCKS5（含 HTTP/3 over UDP ASSOCIATE） | ✅ |
| 代理认证 | ✅ |
| 超时、连接池空闲数 | ✅ |
| multipart（WebKit/Firefox 边界） | ✅ |
| JSON、流式响应 | ✅（wreq 特性） |
| 自定义 DNS / 直连查询 | ✅（`lookup_origin`、`direct_queries`） |
| FTP/SMTP/TELNET 等非 HTTP 协议 | ❌ 不在范围内 |
| curl 配置文件、`--impersonate` 命令行 | ❌ 未提供 CLI |

## 4. 交付形态

| 形态 | 参考项目 | 本仓库 |
|---|---|---|
| 库 | libcurl-impersonate（C ABI） | Rust crate（rlib） |
| 命令行 | `curl-impersonate` + 各浏览器 wrapper 脚本 | 无 bin target；`examples/` 有 8 个演示程序 |
| C ABI 共享库 | ✅ | ✅ 本轮新增 `bindings/ffi`（cdylib + `rci.h`，已用 Python ctypes 实测） |
| 预编译二进制 / CI | ✅ 多平台 release | ✅ `.github/workflows/release.yml`，`v*` tag 产出 9 个平台的 cdylib（桌面/服务器目标另附 `echo`）与 `SHA256SUMS` |
| 官方 Python/Node 绑定 | curl_cffi、impers | ❌ 本轮提供 C ABI 作为封装起点 |

## 5. 编译与封装状态（实测）

- `cargo build --release`：通过，产出 `librust_curl_impersonate.rlib`（约 7.5 MB）。
- `cargo build --release --examples`：通过，`echo` 等示例是可执行二进制（约 9.9 MB，
  BoringSSL 静态链接）。
- `cargo build -p rust-curl-impersonate-ffi --release`：通过，产出
  `librust_curl_impersonate_ffi.so`（约 9.9 MB）。
- Python `ctypes` 调用 `rci_get("chrome150", "https://tls.peet.ws/api/all")`：
  HTTP 200、`h2`、UA `Chrome/150.0.0.0`、JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`、
  Akamai h2 `1:65536;2:0;4:6291456;6:262144|15597570|0|m,s,a,p`。
- 证据：`goal-evidence/binary-and-ffi.txt`。

## 6. 其他语言封装

**可以开始。** 推荐路径：

1. **Python / Node / Go / Java**：通过 `bindings/ffi` 的 C ABI。Python 用 `ctypes`
   或 `cffi`，Node 用 `ffi-napi`/`koffi`，Go 用 cgo，Java 用 JNA/Panama。
2. **Rust 绑定框架**：Python 用 PyO3、Node 用 napi-rs、Swift/Kotlin 用 UniFFI，
   直接依赖本 crate，不需要走 C ABI。
3. **C++**：直接 `#include "rci.h"` 链接 `.so`。

封装时必须注意：

- **异步**：本库是 async（Tokio）。C ABI 版本内部自建 runtime 并阻塞调用；
  高性能场景应复用 `RciClient` 句柄（一次建 runtime），不要把 `rci_get` 放进热路径。
- **内存**：所有返回字符串由库分配，必须调用 `rci_string_free`；句柄用
  `rci_client_free`。
- **错误**：统一返回 `{"error": "..."}` JSON；句柄创建失败用 `rci_last_error()`。
- **无需 vendor patch**：本 crate 的 `Cargo.toml` 直接依赖仓库内的
  `vendor/wreq`、`vendor/quinn`、`vendor/quinn-proto`（`vendor/quinn` 也改为
  path 依赖 `vendor/quinn-proto`），不再使用 `[patch.crates-io]`。独立项目用
  path 或 git 依赖指向本仓库即可直接编译，不需要了解或复制任何 patch
  （已用独立 path 消费者与 git 消费者零配置实测）。
- **发布到 crates.io 前**：crates.io 不接受 path 依赖，届时需要把 `vendor/`
  下的修改上游化，或改为发布 fork 后引用。GitHub Releases 的二进制分发不受
  此限。
- **交叉编译**：BoringSSL 需要目标平台的 C 工具链；产物约 10 MB/平台（静态链接
  BoringSSL），移动端需按 ABI 分别构建。

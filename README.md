# rust-curl-impersonate

用纯 Rust 重写 [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate) 的全部指纹能力，然后在此之上增加上游没有的 profile。

curl-impersonate 不是一个独立的库，而是打在 curl 8.23.0 上的一组补丁，外加一份改过的 BoringSSL。指纹行为因此分散在三个地方：preset 数据表、curl 里把选项转给 TLS 栈的接线、BoringSSL 里真正改 ClientHello 的代码。本仓库按这个边界分层重写，而不是逐文件翻译 C。

## 上游有多大

测量自 `main`（2026-10），补丁相对 curl 8.23.0：

| 补丁 | 规模 | 内容 |
|---|---|---|
| `patches/curl.patch` | 90 个文件，+10,411 / −557 | 见下表 |
| `patches/boringssl.patch` | 18 个文件，+893 / −72 | 扩展顺序、GREASE、delegated credentials、key share 限制、证书压缩、ECH |
| `patches/ngtcp2.patch` + `nghttp3.patch` | +约 900 | HTTP/3 |

`curl.patch` 的新增行按职责：

| 职责 | 行数 | 本仓库对应 |
|---|---:|---|
| preset 数据表 `lib/impersonate.c` | 3,165 | `src/profile.rs` |
| 选项与 API 表面（`curl_easy_impersonate`、`CURLOPT_*`） | 1,350 | 客户端 API，未写 |
| TLS 接线 `lib/vtls/openssl.c` | 1,211 | 取决于所选 TLS 后端 |
| HTTP/3 QUIC `lib/vquic/*` | 1,185 | 未写 |
| WebSocket 握手指纹 `lib/ws.c` | 1,124 | 未写 |
| 头顺序、cookie 拆分、form boundary | 644 | 未写 |
| SOCKS5 UDP ASSOCIATE（HTTP/3 over SOCKS） | 522 | 未写 |
| HTTP/2 SETTINGS、伪头顺序、window update | 233 | 未写 |
| CLI、文档、构建系统 | ~800 | 不移植 |

最后一行是唯一故意不移植的部分。其余每一行都在范围内，包括 WebSocket、SOCKS5 UDP 和 HTTP/3——这三块是指纹面的一部分，不是附属功能。

## 现状

只完成了数据层的第一份样本。`Profile::find("chrome150")` 返回从 `lib/impersonate.c` 逐字段抄录的 Chrome 150 preset，覆盖 cipher、曲线（含 `X25519MLKEM768`）、签名算法、HTTP/2 SETTINGS、HTTP/3 传输参数、QUIC 初始包号、GREASE ECH 和默认头。

**没有任何代码把这些字段写进真实的 ClientHello。** 现在发请求仍然走 `requests-core` 里的 `libcurl-impersonate` 动态库。

## 为什么不能直接写

rustls 不暴露 ClientHello 的构造：cipher 顺序、扩展顺序、GREASE、key share 数量、delegated credentials、证书压缩、ECH 都改不了。这正是 BoringSSL 那 893 行补丁存在的原因。

纯 Rust 重写因此有两条路：

1. **BoringSSL 绑定**，例如 [`wreq`](https://crates.io/crates/wreq)。指纹能力现成，但链接的是 C 库，和「纯 Rust」冲突，而且和同进程的 OpenSSL 有符号冲突。
2. **改 rustls 的 fork**，例如 [`rquest`](https://github.com/0x676e67/rquest) 的路线。真正纯 Rust，但要自己维护 ClientHello 的构造，上游 rustls 每次升级都要重做。

未决定。决定之前不引入 TLS 依赖。

## 路线

1. **数据层**：把 48 个上游 preset 全部转录进 `PROFILES`，加一个测试，断言每个 preset 的字段和 `impersonate.c` 一致。
2. **超出上游的 profile**：上游已经包含 `chrome150`、`chrome151`、`chrome152`（含 macOS 变体）。本仓库要新增的是上游没有的版本，每个都要有真实浏览器抓到的 ClientHello 作为依据，不靠推测。
3. **TLS 后端**：选定上面两条路之一，让 `chrome150` 的 cipher、曲线、扩展顺序、GREASE 在 tls.peet.ws 的回显里对得上。
4. **HTTP/2**：SETTINGS、伪头顺序、window update、priority。
5. **HTTP/3**：QUIC 传输参数、CID 长度、initial packet number。
6. **WebSocket**：permessage-deflate 与 `ws_*` 字段。
7. **SOCKS5 UDP ASSOCIATE**：让 HTTP/3 走 SOCKS5 代理。

每一步的验收标准都是第三方回显，不是单元测试。

## 构建

```bash
cargo test
```

无第三方依赖。

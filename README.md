# rust-curl-impersonate

用 Rust 重写 [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate)。

curl-impersonate 是打在 curl 8.23.0 上的一组补丁，加上一份改过的 BoringSSL。指纹能生效是因为 BoringSSL 那部分：rustls 不暴露 cipher 顺序、扩展顺序、GREASE、ECH、ALPS、delegated credentials 和证书压缩。本仓库把传输层放在 [`wreq`](https://crates.io/crates/wreq) 上，它链接 BoringSSL 并给出这些控制项，然后在上面重写 curl 那一层：选择浏览器预设、套用 TLS 与 HTTP/2 参数、发送请求。

`lib/impersonate.c` 的 48 个预设全部可用，包括 wreq-util 尚未收录的 Chrome 150–152、Firefox 153–155、Safari 260/270、OkHttp 和 Tor。

## 用法

```rust
use rust_curl_impersonate::{Client, Profile};

let profile = Profile::find("chrome150").expect("known target");
let client = Client::new(profile)?;
let response = client.get("https://example.com").send().await?;
println!("{}", response.status());
```

`Profile::find` 接受 `profile::TARGETS` 里的任何一个名字。代理用 `ClientBuilder::proxy`，接受 `http://`、`https://` 和 `socks5://`。WebSocket 用 `Client::websocket`，走同一套 TLS 指纹；`Client::websocket_deflate` 会在握手里带上 `permessage-deflate; client_max_window_bits`。

每个预设按 `lib/impersonate.c` 的顺序发送默认请求头。上传表单用 `FormBoundary::WebKit` 或 `FormBoundary::Firefox`，分别生成 `------WebKitFormBoundary` 加 16 位字母数字、`------geckoformboundary` 加 32 位十六进制的分隔符，与 curl-impersonate 的 `form_boundary` 一致。Cookie 在 HTTP/2 上按每个 cookie 一个 `Cookie` 头发送，对应 `split_cookies`。

`tools/gen_profiles.py` 从 `patches/curl.patch` 里 `impersonations[]` 的新增行重新生成 `src/profile/generated.rs`。

## 已验证

`cargo run --example echo <target>` 对 `https://tls.peet.ws/api/all` 发一次请求，服务器回显的握手与预设一致：

| 预设 | 回显核对 |
|---|---|
| `chrome150` | JA4 `t13d1515h2`，首个 cipher 为 GREASE，曲线 `X25519MLKEM768:X25519:P-256:P-384`，扩展 65037（ECH）与 17613（ALPS 新 codepoint），HTTP/2 SETTINGS `1:65536;2:0;4:6291456;6:262144`，伪头 `m,a,s,p`，UA Chrome/150.0.0.0 |
| `firefox133` | 扩展顺序 `0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27-65037` 逐项一致，含 delegated credentials (34)、record_size_limit (28)、compress_certificate (27)；曲线含 `X25519MLKEM768`、`P-521`、`ffdhe2048`、`ffdhe3072`；HTTP/2 SETTINGS `1:65536;2:0;4:131072;5:16384`，伪头 `m,p,a,s` |
| `safari180` | HTTP/2 SETTINGS `2:0;3:100;4:2097152;8:1;9:1`，含 `ENABLE_CONNECT_PROTOCOL` 与 `NO_RFC7540_PRIORITIES`，伪头 `m,s,a,p`，曲线 `X25519:P-256:P-384:P-521` |

## 传输层表达不了的字段

`profile::deviation` 按预设列出这些差异：

- **ML-DSA 签名算法。** Chrome 150 及更新的预设把 `mldsa44:mldsa65:mldsa87` 放在签名算法列表开头。wreq 链接的 BoringSSL 实现了 ML-DSA，但 TLS 层没有这三个算法的 code point 和名字映射，设置后握手直接失败（`INVALID_SIGNATURE_ALGORITHM`）。这些预设因此去掉它们。code point 仍是草案，没有稳定值，硬编码会让服务器无法识别。
- **HTTP/3 与 SOCKS5 UDP ASSOCIATE。** 10 个预设带 HTTP/3 SETTINGS、QUIC 传输参数和初始包号。Rust 生态里能用的 QUIC 栈是 quinn，它的 TLS 只有 rustls，而 rustls 不能定制 ClientHello；wreq 不暴露 BoringSSL 的 `SSL_set_quic_method`。curl-impersonate 自己的 QUIC 也是借 ngtcp2 实现的。SOCKS5 的 TCP 代理可用。

## 构建

```bash
cargo test
cargo run --example echo chrome150
```

`wreq` 在编译期构建 BoringSSL，首次编译需要 C 编译器和 cmake，耗时几分钟。

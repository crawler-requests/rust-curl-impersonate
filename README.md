# rust-curl-impersonate

用 Rust 重写 [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate)，并在它的预设之外增加浏览器版本。

curl-impersonate 是打在 curl 8.23.0 上的一组补丁，加上一份改过的 BoringSSL。指纹能生效是因为 BoringSSL 那部分：rustls 不暴露 cipher 顺序、扩展顺序、GREASE、ECH、ALPS 和证书压缩。本仓库因此把传输层放在 [`wreq`](https://crates.io/crates/wreq) 上，它链接 BoringSSL 并给出这些控制项，然后在上面重写 curl 那一层：选择浏览器预设、套用 TLS 与 HTTP/2 参数、发送请求。

## 用法

```rust
use rust_curl_impersonate::{Client, Profile};

let client = Client::new(Profile::Chrome150)?;
let response = client.get("https://example.com").send().await?;
println!("{}", response.status());
```

`Profile::Chrome149` 委托给 wreq-util，它自带 Chrome、Edge、Firefox、Safari、Opera 和 OkHttp 的预设。`Profile::Chrome150` 是本仓库新增的：wreq-util 停在 Chrome 149，而 curl-impersonate 的 `lib/impersonate.c` 有 `chrome150`。

代理用 `ClientBuilder::proxy`，接受 `http://`、`https://` 和 `socks5://`。WebSocket 用 `Client::websocket`，走同一套 TLS 指纹。

## 已验证

`cargo run --example echo` 对 `https://tls.peet.ws/api/all` 发一次 Chrome 150 请求，服务器回显的握手与 curl-impersonate 的 `chrome150` 预设一致：

| 字段 | 预设值 | 回显 |
|---|---|---|
| 协议 | HTTP/2 | `h2` |
| JA4 | Chrome 桌面形态 | `t13d1515h2_…` |
| 首个 cipher | GREASE | `TLS_GREASE (0x7A7A)` |
| 曲线 | `X25519MLKEM768:X25519:P-256:P-384` | 顺序一致，含 GREASE |
| ECH | `ech = "true"` | 扩展 65037 |
| ALPS | 新 codepoint | 扩展 17613 `application_settings` |
| HTTP/2 SETTINGS | `1:65536;2:0;4:6291456;6:262144` | 逐项一致 |
| 伪头顺序 | `m,a,s,p` | `:method,:authority,:scheme,:path` |
| User-Agent | Chrome/150.0.0.0 | 一致 |

## 与 curl-impersonate 的差距

curl-impersonate 的 `chrome150` 预设在签名算法列表开头放了 `mldsa44:mldsa65:mldsa87`。wreq 链接的 BoringSSL 不认识这三个名字，设置后握手直接失败（`INVALID_SIGNATURE_ALGORITHM`）。`Profile::Chrome150` 因此去掉它们，并在 [`CHROME150_UNSUPPORTED_SIGALGS`](src/profile.rs) 里记录。要补上这一项，需要换一份打过 curl-impersonate 的 `patches/boringssl.patch` 的 BoringSSL。

其余未覆盖的部分：

- **HTTP/3。** wreq 没有 QUIC 栈，所以预设里的 HTTP/3 SETTINGS、QUIC 传输参数、初始包号和 CID 长度没有地方可写。
- **SOCKS5 UDP ASSOCIATE。** 它只为 HTTP/3 over SOCKS5 服务，同样受限于没有 QUIC。SOCKS5 的 TCP 代理可用。
- **其余 47 个预设。** `lib/impersonate.c` 有 48 个目标。wreq-util 覆盖了其中大部分的浏览器家族，但版本号并不一一对应；本仓库目前只把 `chrome150` 按 curl-impersonate 的数据单独建了预设。
- **任意 JA3 字符串。** 指纹在创建客户端时固定，不支持逐请求覆盖。

## 构建

```bash
cargo test
cargo run --example echo
```

`wreq` 在编译期构建 BoringSSL，首次编译需要 C 编译器和 cmake，耗时几分钟。

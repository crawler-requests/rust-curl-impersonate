# 基于本仓库封装上层库的指引

本文回答「我要在 rust-curl-impersonate 上面再做一个语言级/框架级封装，该怎么做」。
`docs/embedding.md` 讲的是「怎么调用」（函数表、各语言示例）；本文讲的是
**选哪条路径、封装层要补什么、哪些地方会踩坑**。文中每个数字都是 2026-11-27
在本机 `target/release/librust_curl_impersonate_ffi.so`（ABI 2）上实测的。

---

## 1. 先选路径：三条，按封装的语言分

| 封装的语言 | 走哪条 | 理由 |
|---|---|---|
| Rust（含 PyO3 / napi-rs / UniFFI） | **直接依赖 crate**，`Client` 的 async API | 零 IPC、零 JSON 序列化、能拿到全部 `ClientBuilder` 旋钮；C ABI 只暴露了其中一小部分 |
| Python / Node / Go / Java / C# / PHP / Ruby / … | **C ABI 共享库**（`bindings/ffi`） | 每个平台都有成熟 FFI 层（ctypes / koffi / cgo / JNA / P/Invoke / PHP FFI） |
| iOS / Android App、单文件 CLI | **C ABI 静态库**（`.a` / `.lib`） | App 里带 `.so` 在 iOS 上受限、在 Android 上要额外打包 |

不要做的：

- 不要在语言层自己实现 TLS/HTTP 指纹。指纹逻辑只有 Rust 这一份，语言层只应
  原样转发 `profile` 名字。
- 不要把 C ABI 包成「一个请求一个子进程」的 CLI 再在语言里调。C ABI 已经是
  进程内调用（本地 keep-alive 下一整个 `rci_get` 往返 0.5 ms），绕 CLI 会多一次
  进程启动和一套 JSON 协议。
- 不要在封装里自己拼 `Client-Id`/`Trace-Id` 之类的头去"证明"指纹。指纹是否生效
  只能看完美回显：`rci_get(profile, "https://tls.peet.ws/api/all")` 返回的
  回显里 `tls.ja4` 与 `http2.akamai_fingerprint` 与抓包一致。

---

## 2. C ABI 能给你什么，不能给你什么

ABI 2 有 17 个函数（全表见 `docs/embedding.md` §2）。封装的**能力边界**就在这张
表上，先看清再决定要不要自己加函数：

**有：** 48 个预置 + 库里全部记录的枚举与元数据、带选项建句柄（超时/代理/默认头/
重定向策略/cookie 拆分/http1_only）、带逐请求头与任意方法的请求、二进制安全响应
（非 UTF-8 走十六进制）、一次性 GET、HTTP/3 GET、最近响应头、cookie 变更与
重定向历史、运行时注册指纹记录、句柄释放、线程局部错误串。

**没有（要用 Rust API）：** `ClientBuilder` 上约 60 个指纹旋钮（cipher/曲线/签名
算法顺序、扩展顺序、GREASE、ALPS、ECH grease、证书压缩、HTTP/2 SETTINGS、
HTTP/3 传输参数、multipart 边界、WebSocket 某一路的头与 TLS）、WebSocket 升级、
multipart 表单、流式响应、自定义根证书、mTLS 客户端证书、`VersionPool` 版本池、
Provider 注册表除「追加一份 JSON」以外的操作。

封装到需要上面任何一项时，两条路：**在 Rust 侧加函数扩 ABI**（推荐，见 §7），
或者由封装层起一个 Rust 小进程/插件做这些事（不推荐，理由同 §1）。

---

## 3. 封装层真正要补的四件事

C ABI 本身很薄，一个好封装的价值在下面四处。

### 3.1 句柄生命周期与线程

- **一个句柄持有自己的 Tokio runtime 和连接池。** 建句柄本身很便宜（0.031 ms
  中位数，n=200），但「每请求新建」会丢掉 keep-alive 和 cookie。实测对本地服务
  复用句柄 0.13 ms/请求、每次新句柄 0.40 ms/请求（相当）；对 HTTPS 差距是数量级的：
  同一站点 10 次采样，复用句柄中位数 149 ms、每次新句柄 582 ms（新句柄每次都要
  重新握手）。**热路径复用句柄。**
- **`rci_get` 是一次性的**：建句柄→请求→释放，**不跨请求保留 cookie、连接或
  重定向历史**。实测先 GET 一个 `Set-Cookie` 的地址，再 `rci_get` 另一地址，
  回显的 `Cookie` 为 `null`；换成复用同一个 `rci_client_new` 句柄，cookie 正常带上。
- **一个句柄可以被多线程同时调用**（内部在句柄自己的 runtime 上 `block_on`）。
  实测 8 个线程各发一个请求、服务端延迟 250 ms，共享一个句柄时墙钟 253 ms
  （与「一线程一句柄」的 253 ms 相同）；6 个线程 × 40 个带不同标记头的 POST
  也零串包。这是并发快照，不是长期保证——封装仍应把句柄按线程或连接池分配，
  并保证**释放句柄时没有别的线程还在用它**。
- **`rci_last_error()` 是线程局部的**，只记「建句柄失败」；请求失败看返回 JSON 的
  `error` 字段，不要读它。

### 3.2 响应体的二进制安全

返回 JSON 里 `body_is_text: false` 时 `body` 是**小写十六进制**。实测 2 MB 二进制
body 走十六进制再解码，一次 14 ms（含 JSON 解析），没有截断。封装必须在这一步
解十六进制，**不要**当成文本透传。

顺带两点实测行为，封装层的 API 文档要写明：

- 传输层会自动解 gzip/brotli/zstd（前提是 profile 本身广告了 `accept-encoding`），
  返回的头里**没有** `content-encoding` 与 `content-length`，body 是解压后的。
- 服务端返回 3xx 时，默认**不跟随**（返回 `status: 302` 和 `location` 头）。
  要跟随必须传 `follow_safe`；`follow_redirects` 目前**不改变行为**，封装里不要
  把它当成开关暴露出去，或者干脆不映射这个键。

### 3.3 错误模型

- 只有 `rci_client_new*` 失败返回 `NULL`（原因读 `rci_last_error()`）。
- 其余函数**永远**返回 JSON 字符串，失败是 `{"error":"..."}`，不会返回 `NULL`
  （传 `NULL` 句柄也一样给 `{"error":"null client handle"}`）。
- 封装应把这两种合成一种异常/错误类型，并保留原文：`no_cipher_match`、
  `redirect address is blocked`、`HTTP/3 is unavailable`、`unknown profile x`
  这类字符串是使用者排查的唯一线索。
- `rci_load_fingerprints` 现在**在注册时就校验整份文档**（见 §6），所以「加载
  成功」可以当成「这份记录真的能发出去」——封装可以利用这一点做启动期自检。

### 3.4 内存所有权

`char *` 返回值一律由库分配，只能 `rci_string_free`；句柄只能 `rci_client_free`。
语言侧最容易踩的坑是**让运行时的字符串类型接管所有权**：

| 语言 | 错误做法 | 正确做法 |
|---|---|---|
| Python ctypes | `restype = c_char_p` | `restype = c_void_p`，读 `string_at` 后 free |
| Java JNA | 声明成 `String` | 声明成 `Pointer`，`getString` 后 free |
| Node koffi | 声明成 `str` | 声明成 `void *`，`koffi.decode` 后 free |
| C# | 返回 `string` | 返回 `IntPtr`，`Marshal.PtrToStringUTF8` 后 free |
| Go cgo | `*C.char` 直接 `C.GoString` 后 free（可以，但别让 GC 接管） | `defer C.rci_string_free(p)` |

`const char *rci_last_error()` 是例外：不归调用方，直接读即可。

---

## 4. 语言侧的最小可复现路径（都实测过）

工具链只要 C 编译器 + 对应运行时。以下命令都在本机跑通过。

```sh
# 1) 构建共享库
cargo build -p rust-curl-impersonate-ffi --release   # target/release/librust_curl_impersonate_ffi.so，12 MB

# 2) 起一个离线测试服务器（归档里也有同一份）
python3 bindings/ffi/python/testserver.py 8765 &

# 3) 每种语言至少跑通「200 + 版本 + 二进制 body」
```

- **C**：`gcc -I bindings/ffi main.c -L target/release -lrust_curl_impersonate_ffi -Wl,-rpath,'$ORIGIN'`
  实测输出 `abi 2` 与 200。
- **C++**：同上，`g++`。
- **静态链接**：`g++ -x c main.c -x none -L … -l:librust_curl_impersonate_ffi.a -lpthread -ldl -lm`
  实测产出一个 42 MB 的单文件；`.a` 未 strip 时 115 MB，`strip --strip-debug` 后 51.5 MB，
  归档里已处理过。
- **Python**：`bindings/ffi/python/rci_bindings.py` 加载时直接解析 `rci.h`，17 条签名
  自动到位；19 个用例 + 1 个可选 HTTP/3 用例。
- **Java**：`bindings/ffi/java` 是独立 Maven 工程，JNA + 零 JSON 依赖，16 个 JUnit 用例。
- **Node**：`koffi` 3.3.8 实测同步调用返回 200；`fn.async(...)` 还能把调用挪到
  线程池，实测 250 ms 的请求期间主线程定时器照常触发（回调式或 `await` 包装均可）。
- **Go**：cgo 编译器会**拒绝**把 `void *` 传回 `void *` 形参，所以句柄的 C 类型
  必须照 `rci.h` 声明成 `RciClient *`（或 `char *`），不能自己写成 `void *`。
  `tools/gen_signatures.py --go` 生成的声明块加上 `#include <stdlib.h>` 后可被
  `cc -Wextra -Werror` 编译，但块里没有 `stdlib`——因为 `C.free` 需要它。
- **PHP 8.3 FFI**：`FFI::cdef` 内联精简声明可跑通（实测返回 200、`POST` 的
  逐请求头也生效）；`rci.h` 里的注释和 `#include` PHP 解析不了，不要直接喂给它。
- **Rust 封装**：直接依赖 crate 即可，`Response` / `RequestBuilder` /
  `MultipartForm` 都已从 crate 根导出（`rust_curl_impersonate::Response`），
  不需要再单独加一条 `wreq` 依赖去命名类型。

验证指纹是否正确：`chrome150` 对 `https://tls.peet.ws/api/all` 应得到
`ja4 = t13d1516h2_8daaf6152771_d8a2da3f94cd`、
`akamai = 1:65536;2:0;4:6291456;6:262144|15597570|0|m,s,a,p`。对不上说明封装里
`profile` 没传到。

---

## 5. 需要跨请求状态时，状态放在封装层

句柄持有连接池、cookie 罐和 session ticket；C ABI 没有「导出/导入 cookie jar」。
实测结论：

- **同一句柄**：cookie 自动带上（`rci_client_activity` 里能看到 `SET\t…` 行）。
- **换句柄**：cookie 丢失，`rci_get` 也丢。
- **并发**：一个句柄既能被多线程共享，也就意味着它承载的 cookie 罐是共享的——
  多租户场景要么一句柄一租户，要么在封装层自己维护 cookie 并用逐请求头
  （`rci_request_with` 的 `headers_json`）显式带上。

重定向历史同理只挂在句柄上（`rci_client_activity` 的 `redirects`），且只有
`follow_safe` 打开时才有记录。

---

## 6. 你可能会撞上的已知行为（都在库里，不是封装能修的）

按「封装者最可能遇到」排序，每条后面的括号是实测证据形式：

1. **`http1_only` 现在真的生效了**（2026-11-27 修复）：此前 wreq 的 per-profile
   ALPN 列表压过了连接器偏好，`chrome150` 带 `http1_only: true` 仍协商 h2。
   现在会在 `prepare` 里把 ALPN 列表收敛到 `http/1.1`，实测返回 `HTTP/1.1`。
   记录本身没有 ALPN 的（`node22_https`、`java21_urlconn` 等）保持不发 ALPN。
2. **`follow_redirects` 不改变行为**：默认 302 原样返回；只有 `follow_safe`
   才跟随，且解析到环回/私网/链路本地会报 `redirect address is blocked`。
3. **同名头后者胜**：`headers` 与逐请求头数组都是后者胜，实测
   `[["x","1"],["x","2"]]` 发出的是 `x: 2`。要发出多条同名头目前只有一条路：
   让 `split_cookies` 把 `Cookie` 拆开。
4. **`version` 是服务端协商结果，不是 profile 能力**：h2 profile 连只支持
   HTTP/1.1 的服务端会返回 `"HTTP/1.1"`。判断 profile 是否带 HTTP/3 配置要看
   `rci_profile_info(name).has_http3`。
5. **HTTP/3 需要 profile 自带 QUIC 配置**：没有的 profile 调 `rci_http3_get`
   返回 `{"error":"HTTP/3 is unavailable"}`，不会静默降级。`quic.nginx.org`
   会按源 IP 限流（实测 4 次里 1 次 200、其余 `260 H3_REQUEST_REJECTED`），
   封装层的重试要能识别这种错误。
6. **请求方法没有校验**：`rci_request` 会把任何方法名原样发出，拼错的方法
   （如 `FROBNICATE`）由服务端回 501，库不报错。封装层应当自己校验方法名。
7. **BoringSSL 的 cipher 列表至少要一条 TLS 1.2 套件**：只写
   `TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384` 会得到 `NO_CIPHER_MATCH`。
   自定义记录时注意（库里 0 条记录是 TLS 1.3-only 的）。
8. **`rci_load_fingerprints` 现在整份校验**（2026-11-27 修复）：未知的
   cipher/曲线/签名算法、坏 ALPN、坏扩展 id、坏 TLS 版本都会让整份文档在注册时
   被拒；此前 cipher/曲线/签名算法名要等到建句柄才暴露。

---

## 7. 需要 ABI 没有的能力时，怎么扩

按顺序做，别跳步：

1. **先看 Rust API 有没有**：`ClientBuilder` 上每个 `pub fn` 都对应一个线上字段
   （`src/client.rs` 的 builder 段）。大部分指纹旋钮已经在那里。
2. **在 `bindings/ffi/src/lib.rs` 加函数**：照现有函数的模式——
   `guarded(AssertUnwindSafe(...))` 包住、返回 `into_c_string(...)`、
   句柄类操作走 `off_runtime(...)`（在已进入 runtime 的线程上调用会 abort）、
   新键加进 `Options`（`deny_unknown_fields` 会替你拒绝拼错的键）。
3. **同步改三处**：`bindings/ffi/rci.h`（权威声明）、
   `bindings/ffi/java/.../RciLibrary.java`（可跑 `python3 tools/gen_signatures.py --check`
   看缺哪条，`--java` 会打印方法体）、以及 `rci_version()` 的 ABI 版本号
   ——**加函数也要 bump**，否则下游无法判断新函数是否存在。
4. **跑门禁**：`cargo test -p rust-curl-impersonate-ffi`、`gen_signatures.py --check`、
   Python/Java 两套封装测试、以及 `nm -D` 与头文件的比对（CI 的 `ffi` job 全做）。
5. **改文档**：`docs/embedding.md` §2 的全表、`rci.h` 的注释、`PROGRESS.md` 一条。

`bindings/ffi/python/rci_bindings.py` 不用改：它在加载时读 `rci.h`，新函数自动可用。
Java 一侧要手改（工具会告诉你缺什么）。

---

## 8. 发布形态

- **二进制**：每个 `v*` tag 由 GitHub Actions 构建 18 个平台，归档里已经有
  `include/rci.h`、动态库、静态库、Python 封装、Java 工程、`EMBEDDING.md`。
  封装只要从 Release 下载对应归档，或用包里自带的 `rci_bindings.py` 直接起步。
- **crates.io**：现在不行。crate 依赖仓库内的 `vendor/wreq`、`vendor/quinn`，
  path 依赖发布不上去；需要先把 vendor 改动上游化或发布 fork。
  GitHub Releases 分发不受此限。
- **许可证**：本仓库 MIT。归档里的 `LICENSE` 随包分发即可；你的封装层用什么
  许可由你决定，但必须在文档里说明底层库的 MIT 归属。

---

## 9. 一张验收清单

封装完成前，逐条过：

- [ ] 48 个预置名与库里记录名都能枚举（`rci_targets` / `rci_profiles`），
      并能查到 `family/platform/fidelity/has_http3/deviation`
- [ ] `rci_get("chrome150", "https://tls.peet.ws/api/all")` 的 JA4 与 Akamai h2
      与抓包逐字符一致
- [ ] 2 MB 二进制 body 解十六进制后字节数不变（`content()` 类 API）
- [ ] 复用句柄的第二个请求带上了第一个响应的 `Set-Cookie`
- [ ] 断网/403/未知 profile 都返回你的错误类型且保留原文
- [ ] 300 ms 超时对 1.5 s 的慢服务确实超时（`timeout_ms`）
- [ ] 并发：N 个线程共享一个句柄，响应不串包；句柄只在自己的线程/生命周期内释放
- [ ] 在 async 运行时里调用不 abort（Rust 封装必测，有回归测试可参考）
- [ ] `rci_last_error` 不被当成请求错误来源
- [ ] HTTP/3：`has_http3: false` 的 profile 给出明确错误而不是静默降级

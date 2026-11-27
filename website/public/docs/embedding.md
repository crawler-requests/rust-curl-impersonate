# 把 rust-curl-impersonate 内嵌进其它语言

本库的指纹逻辑只有 Rust 这一份实现。其它语言通过一份 **C ABI 共享库**
（或静态库）使用它：一个 `.so` / `.dylib` / `.dll`，加一个 `rci.h`。

- 想直接用 Rust：[README](../README.md) 里的 `Client` / `Profile`。
- 想看完整函数语义：[bindings/ffi/README.md](../bindings/ffi/README.md)。
- 想加自己的指纹记录但不发版：[provider-protocol.md](provider-protocol.md)。

本文档回答三件事：**底层到底暴露了哪些函数和签名**、**这些函数返回的 JSON
长什么样**，以及**每种语言怎么把库接进来**。文中「已实测」的说法，都在本机
同一份 `v0.3.0` 动态库上实际编译并运行过：C（动态/静态）、C++、Python
（ctypes 封装）、Java（JNA 封装，含 HTTP/3）、Node（koffi）、Go（cgo）、
PHP（FFI）。Swift、C#、Android 本机没有对应工具链，那几节按标准写法给出、
未实测。

---

## 0. 先回答「封装时怎么知道底层有什么」

C ABI 没有反射，语言侧能知道的信息只有三处，这份文档把三处都写全了：

| 来源 | 位置 | 机器可读？ |
|---|---|---|
| 权威 C 声明 | 归档内 `include/rci.h` | 是（C 语法） |
| 共享库导出表 | `nm -D` / `readelf -s` / `objdump -T` / `dumpbin /exports` | 是（符号名） |
| 各语言声明文件 | 归档内 `python/rci_bindings.py`、`java/.../RciLibrary.java`、`docs/embedding.md` 各节 | 是 |

检查三者是否一致：

```sh
# 头文件里声明的函数，是否每一个都在动态库里导出
grep -oE 'rci_[a-z0-9_]+' include/rci.h | sort -u > /tmp/declared.txt
nm -D --defined-only lib/librust_curl_impersonate_ffi.so \
  | awk '{print $3}' | sort > /tmp/exported.txt
comm -23 /tmp/declared.txt /tmp/exported.txt      # 应为空

# 签名：以头文件为准，Rust 侧每个参数顺序都与它一一对应
sed -n '/^uint32_t rci_version/,/^void rci_string_free/p' include/rci.h
```

Windows 上 `nm` 不一定有，本仓库带 `scripts/peexports.py`，纯 Python 读 PE 导出表。

### 完整签名从哪来

C ABI 没有反射，语言侧只能从头文件和导出表得到真相。本仓库提供两件工具，
把「头文件是唯一权威」变成可执行的门禁：

**`python/rci_bindings.py` 在加载时直接读 `rci.h`**，把每条 `char *rci_x(...)`
解析成 ctypes 的 `argtypes` / `restype`——头文件新增一条函数，Python 侧不改
代码就跟着出现。解析规则只有两条：`char *` 结果归库所有（用 `c_void_p` 接，
再 `rci_string_free`），`const char *` 结果归调用方（用 `c_char_p` 直接读）。
找不到 `rci.h`（例如只复制了 `.so`）时退回内置的 17 条签名表；
`python/tests/test_rci_bindings.py::test_signatures_match_the_header` 断言
内置表与解析出的头文件逐条相同。

**`tools/gen_signatures.py` 是命令行版，并且是 CI 门禁**：

```sh
python3 tools/gen_signatures.py --check    # Java 的 17 条声明必须与 rci.h 一致
python3 tools/gen_signatures.py --java     # 打印该 Java 接口方法体
python3 tools/gen_signatures.py --go       # 打印一个可编译的 C 声明块（cgo /* */ 里用）
python3 tools/gen_signatures.py --list     # 打印全部函数签名与 ABI 版本
```

`--check` 已经接进 CI：头文件加了函数而 Java 封装没跟，构建就红。Java 封装
本身（`java/`）的测试也在 CI 里跑，所以「文档、头文件、封装」三者不会互相
脱节到把下游坑了。`--go` 的输出已实测能被 `cc -Wall -Wextra -Werror` 编译。

---

## 1. 拿到库

从 [Releases](https://github.com/crawler-requests/rust-curl-impersonate/releases)
下载对应平台归档，解压后（`v0.4.0` 起）：

```
include/rci.h              C 头文件（权威声明）
lib/librust_curl_impersonate_ffi.so    动态库（.dylib / .dll）
lib/librust_curl_impersonate_ffi.a     静态库（Windows 上是 .lib）
python/rci_bindings.py    完整 ctypes 封装（Client / Profile / Response 类）
python/demo.py            最小用法示例
java/                     可发布的 JNA 封装（pom.xml + 源码 + 测试）
EMBEDDING.md              本文档
USING_THIS_ARCHIVE.md     归档级说明
README.md                 完整函数表
```

### 支持的平台（18 个）

| 系统 | 架构 | 归档 target |
|---|---|---|
| Linux (glibc) | x86_64 | `x86_64-unknown-linux-gnu` |
| Linux (glibc) | aarch64 | `aarch64-unknown-linux-gnu` |
| Linux (glibc) | armv7 硬浮点 | `armv7-unknown-linux-gnueabihf` |
| Linux (glibc) | i686 | `i686-unknown-linux-gnu` |
| Linux (musl) | x86_64 | `x86_64-unknown-linux-musl` |
| Linux (musl) | aarch64 | `aarch64-unknown-linux-musl` |
| macOS | x86_64 | `x86_64-apple-darwin` |
| macOS | arm64 | `aarch64-apple-darwin` |
| Windows | x86_64 | `x86_64-pc-windows-msvc` |
| Windows | arm64 | `aarch64-pc-windows-msvc` |
| Windows | i686 | `i686-pc-windows-msvc` |
| Android | arm64-v8a | `aarch64-linux-android` |
| Android | armeabi-v7a | `armv7-linux-androideabi` |
| Android | x86_64 | `x86_64-linux-android` |
| Android | x86 | `i686-linux-android` |
| iOS | 真机 arm64 | `aarch64-apple-ios` |
| iOS | 模拟器 arm64 | `aarch64-apple-ios-sim` |
| iOS | 模拟器 x86_64 | `x86_64-apple-ios` |

`armv7-musl` 与 `i686-musl` 不提供：上游 `btls` crate 在 32 位 musl 上无法编译
（把 `i64` 传给 `time_t`）。需要这两个组合时，用对应的 glibc 构建。

### 动态库还是静态库

| | 动态（`.so`/`.dylib`/`.dll`） | 静态（`.a`/`.lib`） |
|---|---|---|
| 分发 | 库文件要和程序一起发 | 链接进程序自己的二进制 |
| 适用 | Python / Node / Java / PHP 等运行时加载 | iOS App、Android App、单文件 CLI、不想附带 .so 的场景 |
| 注意 | 运行时加载器要能找到（rpath / `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` / 与 exe 同目录） | **必须用 C++ 链接器**，见下 |

**静态库依赖 C++ 运行时**（内含 BoringSSL，是 C++）。用 C 源文件时：

```sh
g++ -x c main.c -x none -L lib -l:librust_curl_impersonate_ffi.a \
    -lpthread -ldl -lm -o app
```

或保留 C 编译器并显式加 C++ 运行时：

```sh
cc main.c -L lib -l:librust_curl_impersonate_ffi.a -lstdc++ -lpthread -ldl -lm
```

（Windows MSVC：`cl main.c rust_curl_impersonate_ffi.lib` 即可，MSVC 自带 C++ 运行时。）

**动态库同样依赖 `libstdc++` / `libgcc_s`**，Linux 极简镜像（如 `scratch`、
无 C++ 运行时的 alpine）要么装 `libstdc++`，要么改用静态库。

---

## 2. native API 全表

ABI 版本 **2**，`rci_version()` 返回它。共 **17 个函数**，全部 `extern "C"`，
签名以 `rci.h` 为准。v1 的全部签名和 JSON 字段在 v2 里保持不变。

下表的「所有权」一列是封装时最容易出错的地方：

| 种类 | 签名 | 返回 | 所有权 |
|---|---|---|---|
| 值 | `uint32_t rci_version(void)` | `2` | 无 |
| 字符串 | `char *rci_targets(void)` | JSON 字符串数组，48 个预设名 | 库持有，`rci_string_free` |
| 字符串 | `char *rci_profiles(void)` | JSON 字符串数组，预置 + 库记录全部名字 | 库持有 |
| 字符串 | `char *rci_profile_info(const char *name)` | JSON 对象或 `{"error"}` | 库持有 |
| 句柄 | `RciClient *rci_client_new(const char *profile)` | 句柄或 `NULL` | 调用方持有，`rci_client_free` |
| 句柄 | `RciClient *rci_client_new_with_options(const char *profile, const char *options_json)` | 同上 | 同上 |
| 无 | `void rci_client_free(RciClient *h)` | — | 传入 `NULL` 无害 |
| 字符串 | `char *rci_client_profile(RciClient *h)` | 预设名字符串（裸串，非 JSON） | 库持有 |
| 字符串 | `char *rci_request(RciClient *h, const char *method, const char *url, const uint8_t *body, size_t body_len)` | 响应 JSON | 库持有 |
| 字符串 | `char *rci_request_with(RciClient *h, const char *method, const char *url, const char *headers_json, const char *body)` | 响应 JSON | 库持有 |
| 字符串 | `char *rci_get(const char *profile, const char *url)` | 响应 JSON（一次性建/发/释） | 库持有 |
| 字符串 | `char *rci_http3_get(const char *profile, const char *addr, const char *host, const char *path)` | 响应 JSON | 库持有 |
| 字符串 | `char *rci_client_last_headers(RciClient *h)` | JSON `[名,值]` 数组 | 库持有 |
| 字符串 | `char *rci_client_activity(RciClient *h)` | JSON 对象 | 库持有 |
| 字符串 | `char *rci_load_fingerprints(const char *json)` | `"{}"` 或 `{"error"}` | 库持有 |
| 字符串 | `const char *rci_last_error(void)` | 线程最近错误串 | 库持有，**不要释放** |
| 无 | `void rci_string_free(char *text)` | — | 传入 `NULL` 无害 |

所有 `char *` 返回值**都由库分配**，必须且只能用 `rci_string_free()` 释放；
`rci_request` 等查询函数**不返回 `NULL`**（出错也返回 `{"error":...}` JSON），
只有 `rci_client_new*` 失败时返回 `NULL`，原因读 `rci_last_error()`。

`rci_last_error()` 是**线程局部**的：它只记录「建句柄失败」这一件事，
发出请求失败不会更新它（请求失败看返回的 `error` 字段）。

### 2.1 建客户端的选项（`options_json`）

全部可选，**未知键会报错**（`deny_unknown_fields`），键名拼错会失败而不是被忽略：

```json
{
  "timeout_ms": 30000,
  "proxy": "socks5://127.0.0.1:1080",
  "follow_redirects": true,
  "follow_safe": false,
  "pool_max_idle_per_host": 4,
  "headers": [["accept-language", "zh-CN"]],
  "split_cookies": false,
  "http1_only": false
}
```

| 键 | 类型 | 默认 | 语义（已实测） |
|---|---|---|---|
| `timeout_ms` | 整数 | `30000` | 整个请求的总超时 |
| `proxy` | 字符串 | 无 | `http://`、`https://`、`socks5://`、`socks5h://` |
| `follow_redirects` | 布尔 | `true` | **当前实现里这个键不改变行为**：默认 302 原样返回；只有 `follow_safe` 才会跟随重定向。详见 §6 |
| `follow_safe` | 布尔 | 无 | **`true` 才跟随重定向**，且解析到环回/私网/链路本地就拒绝；`false` 跟随但不做地址过滤 |
| `pool_max_idle_per_host` | 整数 | 无 | 连接池空闲上限 |
| `headers` | `[["名","值"],…]` | `[]` | 加到每个请求；同名替换预设默认头，空值抑制该头 |
| `split_cookies` | 布尔 | 无 | HTTP/2 里每个 cookie 一条 `Cookie` 头 |
| `http1_only` | 布尔 | 无 | 强制 HTTP/1.1 |

`NULL`、`""`、`"{}"`、纯空白都表示「用默认」。实测两处容易踩的行为：

```text
{"headers":[["accept-language","zh-CN"]]}  → 只是替换预设的 accept-language
{"headers":[["user-agent",""]]}            → user-agent 被抑制，预设其余头保留
{"headers":[["x-test","1"],["x-test","2"]]}→ 同名后出现的值生效（x-test: 2）
```

### 2.2 `rci_profile_info` 的 JSON 对象

```json
{
  "name": "go1.26",
  "wire": "go1.26",
  "family": "go",
  "platform": "linux",
  "fidelity": "close",
  "deviation": "BoringSSL always sends the TLS 1.3 cipher suites before …",
  "http1_only": false,
  "has_http3": false,
  "source": "tls.peet.ws capture, tools/capture/raw/go1.26.json"
}
```

- `wire`：实际发出的线路参数来自哪个预置（别名会指向基座）。
- `fidelity`：`"exact"` / `"close"` / `"partial"` / `null`（内置预设为 `null`）。
- `deviation`：抓包里发不出来的字段说明，用 `; ` 连接成一条字符串，没有则 `null`。
- `has_http3`：该 profile 有没有 QUIC 配置，决定 `rci_http3_get` 能否用。
- 未知名字返回 `{"error":"unknown profile <name>"}`。

实测值：`chrome150` → `has_http3: true`、`fidelity: null`；`go1.26` → `has_http3:
false`、`fidelity: "close"`。

### 2.3 响应 JSON

```json
{
  "status": 200,
  "version": "HTTP/2.0",
  "url": "https://example.com/",
  "headers": [["content-type", "text/html"], ["server", "nginx"]],
  "body": "<内容>",
  "body_is_text": true
}
```

- `version`：`"HTTP/0.9"` / `"HTTP/1.0"` / `"HTTP/1.1"` / `"HTTP/2.0"` /
  `"HTTP/3.0"`，其它为 `"unknown"`。
- `url`：经过重定向后的最终地址。
- `headers`：保持到达顺序的 `[名, 值]` 数组；HTTP/2 的同名多值也在这里逐条列出。
- `body_is_text: true` 时 `body` 是 UTF-8 文本；`false` 时 `body` 是**小写十六进制**，
  解成字节即可（这样二进制内容不会被截断或损坏）。
- 失败：`{"error":"..."}`。

`rci_http3_get` 的 `addr` 是 `"ip:port"`（也可以是主机名，会先解析），
`host` 是 SNI 与 `:authority`，`path` 是请求路径。HTTP/3 响应体遵循同一文本/十六进制规则。

### 2.4 句柄内省

| 函数 | 返回 |
|---|---|
| `char *rci_client_last_headers(h)` | 最近一次响应的头，JSON `[名,值]` 数组；未发过请求时是 `[]` |
| `char *rci_client_activity(h)` | `{"cookies":["SET\t…"],"redirects":["302\t…"]}` |

实测：新建句柄后 `last_headers` 是 `[]`、`activity` 是 `{"cookies":[],"redirects":[]}`；
只有 `follow_safe` 打开时重定向才会写进 `redirects`（见 §6）。

### 2.5 运行时加指纹记录

| 函数 | 说明 |
|---|---|
| `char *rci_load_fingerprints(const char *json)` | 把一份库 schema 的 JSON 文档注册进当前进程 |

文档是 `{...}` 单条、`[...]` 列表、或 `{"fingerprints":[...]}` 包装（schema 见
[provider-protocol.md](provider-protocol.md)）。注册后新名字立刻能用于
`rci_client_new`；与内置记录同名时覆盖内置的那条（本进程内，优先级 user=100）。
文档先整体校验再接纳，坏的一份整份拒绝。成功返回 `"{}"`，失败 `{"error":"…"}`。

实测（`goal-evidence/cloud-library.json`）：

```text
注册前 go1.26 source = "tls.peet.ws capture, tools/capture/raw/go1.26.json"
注册后 go1.26 source = "cloud.acme.example/fingerprints, overrides built-in go1.26 until unregistered"
新记录 cloud_premium → wire=chrome150, fidelity=exact
```

---

## 3. Python

归档里的 `python/rci_bindings.py` 是完整封装：`Library`（加载 + 按 `rci.h`
声明签名）、`Profile`（元数据）、`Client`（上下文管理器）、`Response`（
`text` / `content` / `headers` / `status`）、`load_fingerprints`。
可直接复制进项目，`demo.py` 是最小用法。

### 3.1 装进你自己的项目

```python
# myapp/http.py
from rci_bindings import Client          # 把 rci_bindings.py 放进包里

with Client("chrome150", timeout_ms=10_000) as client:
    reply = client.get("https://tls.peet.ws/api/all")
    print(reply.status, reply.version, reply.header("server"))
    if reply.body_is_text:
        print(reply.text[:200])
    else:
        print(len(reply.content), "bytes")   # 二进制 body 自动解十六进制
```

库文件位置：默认按 `lib/` 旁边找，可用 `Library(path=...)` 或环境变量
`RCI_LIB` 指向任意路径（发布包里放在 `python/` 同级即可）。

`Client.request(method, url, headers=..., body=...)` 会按参数挑 ABI 函数：
有逐请求头或有字符串 body 时走 `rci_request_with`，否则走长度分隔的
`rci_request`。ABI 里没有「逐请求头 + 二进制 body」这个组合，所以 Python 层
对这种组合直接报 `ValueError`，而不是悄悄丢掉 body。

### 3.2 不用封装、只用 ctypes 的最小写法

```python
import ctypes, json

lib = ctypes.CDLL("./lib/librust_curl_impersonate_ffi.so")
lib.rci_get.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.rci_get.restype = ctypes.c_void_p          # 不是 c_char_p！
lib.rci_string_free.argtypes = [ctypes.c_void_p]

p = lib.rci_get(b"chrome150", b"https://example.com")
reply = json.loads(ctypes.string_at(p).decode())
lib.rci_string_free(p)
print(reply["status"], reply["version"])
```

要点：

- `restype` 必须是 `c_void_p`。写成 `c_char_p` 会让 ctypes 先复制再丢掉原始指针，
  再调 `rci_string_free` 就是释放野指针。
- `rci_last_error` 返回 `const char*`，用 `c_char_p` 是对的（不释放）。
- 二进制 body：`bytes.fromhex(reply["body"])`，仅当 `body_is_text` 为 `False`。

---

## 4. Java / Kotlin

归档里的 `java/` 是一份**可直接 `mvn package` 的 JNA 封装**：`RciLibrary`
`RciLibrary` 接口声明 17 个函数，`RustCurlImpersonate` 门面类包出
`Profile` / `Settings` / `Client` / `Response`，并带 16 个 JUnit 测试（对本地
测试服务器跑 HTTP/1.x 与 HTTP/2 请求，另有一条真实 HTTP/3 用例）。

### 4.1 Maven 依赖

```xml
<dependency>
  <groupId>net.java.dev.jna</groupId>
  <artifactId>jna</artifactId>
  <version>5.17.0</version>
</dependency>
```

### 4.2 关键约定

> 为什么用 JNA 而不是 Panama（FFM API）：Panama 在 JDK 21 是 preview，
> JDK 22+ 才正式，且要求调用方 `--enable-preview`/`--enable-native-access`。
> JNA 在 JDK 8–25 上没这类限制，所以封装默认用它。需要 Panama 时见 §4.4。

```java
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

public interface RciLibrary extends Library {
    RciLibrary INSTANCE = Native.load("rust_curl_impersonate_ffi", RciLibrary.class);

    int rci_version();
    Pointer rci_targets();                 // 返回值声明成 Pointer！
    Pointer rci_get(String profile, String url);
    void rci_string_free(Pointer text);
}
```

- 返回 `char*` 的函数在 Java 侧一律声明成 **`Pointer`**，自己 `getString` 后
  `rci_string_free`。声明成 `String` 会让 JNA 自动转换并丢掉原始指针，再释放就崩。
- 句柄声明成 `Pointer`（`RciClient` 在 C 里是 opaque struct）。
- 字符串参数用 `String` 即可，JNA 会做 UTF-8 转换；`body_len` 用 `long`（size_t，64 位）。
- `rci_last_error` 声明成 `String` 是**安全**的——它不归调用方释放，JNA 直接拷贝文本。

### 4.3 用法

```java
try (RustCurlImpersonate.Client client = RustCurlImpersonate.client("chrome150")) {
    RustCurlImpersonate.Response r = client.get("https://tls.peet.ws/api/all");
    System.out.println(r.status() + " " + r.version());
    System.out.println(r.bodyText().substring(0, 200));
}
```

`Settings` 是同一组选项的类型化写法（未知字段由库拒绝）。`Response` 的
`content()` 自动把二进制 body 的十六进制解回字节；`header(name)` 大小写不敏感；
`Client.activity()` 返回 cookie 变更与重定向历史。

### 4.4 可选：JDK 22+ 的 Panama

如果项目已经统一到 Panama，函数签名可写成：

```java
MethodHandle rciGet = linker.downcallHandle(
    SymbolLookup.loaderLookup().find("rci_get").orElseThrow(),
    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
// 调用后拿到 MemorySegment，读 UTF-8，再调 rci_string_free(segment)
```

要点与 JNA 一致：返回值当地址处理，释放走 `rci_string_free`。

### 4.5 Android / Kotlin

- `.so` 放 `src/main/jniLibs/<abi>/librust_curl_impersonate_ffi.so`，
  JNA 在 Android 上同样可用（`Native.load` 会自动从 `jniLibs` 找）。
  Android 共享库运行时需要 NDK 的 `libc++_shared.so`。
- 更常见的是走 NDK C++ + JNI：include `rci.h`，在 `.cpp` 里调 17 个函数，
  Kotlin 侧只面对你写的 `external fun`。静态库则不必带 `libc++_shared.so`。

---

## 5. 其它语言

C、C++、Node、Go、PHP 这几节已实测；Swift、C#、Android 本机没有工具链，
命令按公开工具链的标准写法给出，接进来之前先按 §8 跑一次自检。

实测方式：`main.c` 用 `gcc` 动态链接、`g++ -x c` 与 `cc … -lstdc++` 两种静态
链接都跑通（均输出 `abi 2` 与 200）；`main.cpp` 用 `g++` 跑通；Go 经 cgo、
Node 经 koffi、PHP 经 FFI 各返回 HTTP/1.1 200。

### 5.1 C

```c
#include <stdio.h>
#include "rci.h"

int main(void) {
    printf("abi %u\n", rci_version());

    RciClient *c = rci_client_new("chrome150");
    if (!c) { printf("err: %s\n", rci_last_error()); return 1; }

    char *r = rci_request_with(c, "GET", "https://example.com",
                               "[ [\"accept-language\",\"zh-CN\"] ]", NULL);
    printf("%.200s\n", r);      /* {"status":200,…} */
    rci_string_free(r);
    rci_client_free(c);
    return 0;
}
```

```sh
gcc -I include main.c -L lib -lrust_curl_impersonate_ffi \
    -Wl,-rpath,'$ORIGIN/lib' -o app
```

### 5.2 C++

```cpp
#include <cstdio>
#include "rci.h"

int main() {
    char *p = rci_profiles();
    std::printf("%.60s…\n", p);
    rci_string_free(p);
}
```

```sh
g++ -I include main.cpp -L lib -lrust_curl_impersonate_ffi \
    -Wl,-rpath,'$ORIGIN/lib' -o app
```

### 5.3 Node.js（koffi）

```js
import koffi from "koffi";

const lib = koffi.load("./lib/librust_curl_impersonate_ffi.so");
const rci_get = lib.func("void *rci_get(const char *profile, const char *url)");
const rci_string_free = lib.func("void rci_string_free(void *p)");

const p = rci_get("chrome150", "https://example.com");
const reply = JSON.parse(koffi.decode(p, "char", -1));
rci_string_free(p);
console.log(reply.status, reply.version, reply.headers.length);
```

要点：返回值声明成 `void *`，koffi 就不会把它当字符串接管所有权。`ffi-napi` 同理。

### 5.4 Go（cgo）

```go
package main

/*
#cgo LDFLAGS: -L./lib -lrust_curl_impersonate_ffi -Wl,-rpath,${SRCDIR}/lib
#include <stdint.h>
#include <stdlib.h>
extern uint32_t rci_version(void);
extern char *rci_get(const char *profile, const char *url);
extern void rci_string_free(char *text);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

func main() {
	fmt.Println("abi", uint32(C.rci_version()))

	profile := C.CString("chrome150")
	url := C.CString("https://example.com")
	defer C.free(unsafe.Pointer(profile))
	defer C.free(unsafe.Pointer(url))

	out := C.rci_get(profile, url)
	defer C.rci_string_free(out)

	var reply map[string]any
	json.Unmarshal([]byte(C.GoString(out)), &reply)
	fmt.Println(reply["status"], reply["version"])
}
```

要点：`C.CString` 出来的要 `C.free`；库返回的要 `rci_string_free`，用 `defer` 漏不掉。

### 5.5 PHP（FFI，7.4+）

```php
<?php
$h = FFI::cdef("
typedef struct RciClient RciClient;
uint32_t rci_version(void);
char *rci_profile_info(const char *profile);
char *rci_get(const char *profile, const char *url);
void rci_string_free(char *text);
", "./lib/librust_curl_impersonate_ffi.so");

echo "abi ", $h->rci_version(), "\n";
$p = $h->rci_get("chrome150", "https://example.com");
echo substr(FFI::string($p), 0, 200), "\n";
$h->rci_string_free($p);
```

要点：PHP 的 `FFI::cdef` 解析不了 `rci.h` 里的注释与 `#include`，所以内联一份
精简声明（函数名与参数类型必须与 `rci.h` 一致）。

### 5.6 C#

```csharp
[DllImport("rust_curl_impersonate_ffi")]
static extern IntPtr rci_get([MarshalAs(UnmanagedType.LPUTF8Str)] string profile,
                             [MarshalAs(UnmanagedType.LPUTF8Str)] string url);

[DllImport("rust_curl_impersonate_ffi")]
static extern void rci_string_free(IntPtr text);
```

返回 `IntPtr`，再 `Marshal.PtrToStringUTF8`，最后 `rci_string_free`。
Windows 默认按 ANSI 转换，所以要显式 `LPUTF8Str`——`rci.h` 的字符串全是 UTF-8。

### 5.7 Swift（iOS/macOS）

链接静态库 `.a`，在 bridging header 里 `#import "rci.h"` 之后直接用
`rci_client_new` 等函数（Swift 会自动导入 `extern "C"` 声明）。iOS 必须用 `.a`，
App Store 不收随包动态库。返回的 `UnsafeMutablePointer<CChar>` 用完调
`rci_string_free`。

### 5.8 Rust 自身

不想要 C ABI 时直接依赖 crate：

```toml
[dependencies]
rust-curl-impersonate = { git = "https://github.com/crawler-requests/rust-curl-impersonate" }
```

---

## 6. 当前实现里必须知道的差异（实测）

这三条在任何语言封装里都会遇到，且与直觉不一致，值得先看：

1. **重定向默认不跟随。** 建句柄时不给调解选项，访问 302 会**原样返回 302**
   （`follow_redirects` 当前不改变行为）。要跟随重定向，传
   `{"follow_safe": true}`（会拒绝重定向到私网/环回）或 `{"follow_safe": false}`
   （跟随但不过滤地址）。这两种情况都会把重定向写进 `rci_client_activity` 的
   `redirects`；不跟随时不写。
2. **`headers` 里的同名值后者胜。** 想设多值头（例如两条 `Cookie`）用
   `split_cookies: true` 或 `rci_request_with` 的逐请求头数组，不要靠重复键。
3. **`rci_last_error` 只记建句柄失败。** 请求失败看返回 JSON 的 `error`，
   不要读 `rci_last_error`（那里还是上一次建句柄的旧字）。

---

## 7. 通用注意事项

1. **调用是阻塞的**。每个请求等响应才返回。**复用一个句柄**，不要每请求都
   `rci_get`（那会重建 runtime 和连接池）。
2. **线程**：句柄不是线程安全的，一个线程一个句柄；`rci_last_error` 是线程局部的。
3. **内存**：`char *` 返回值用 `rci_string_free`；句柄用 `rci_client_free`。
   两者都允许传 `NULL`。
4. **错误**：请求失败返回 `{"error":"…"}` 的 JSON，不是 `NULL`。只有
   `rci_client_new*` 失败返回 `NULL`，原因读 `rci_last_error()`。
5. **二进制响应**：`body_is_text == false` 时 `body` 是十六进制，别当文本用。
6. **HTTP/3 需要 QUIC 配置**：先用 `rci_profile_info(name).has_http3` 判断；
   没有的 profile 调 `rci_http3_get` 会返回 `{"error":"HTTP/3 is unavailable"}`，
   不会静默退回 HTTP/2。
7. **动态库加载路径**：Linux `rpath`/`LD_LIBRARY_PATH`，macOS
   `@rpath`/`DYLD_LIBRARY_PATH`，Windows 与 exe 同目录即可。
8. **在 async 运行时内调用（Rust 封装必看）**：C ABI 同步、且内部会自建
   runtime 并 `block_on`；在已进入 tokio runtime 的线程上这是非法的。库内已用
   `off_runtime` 把这类调用挪到独立线程，**不会 abort 进程**（回归测试
   `bindings/ffi/tests/abi.rs::calls_from_inside_a_runtime_do_not_abort`），但那条
   线程会阻塞到响应返回。在 Rust 里写封装、且本身跑在 async 服务中时，优先像
   §5.8 那样直接用 Rust 异步 API（`spawn_blocking` 只在必须用 C ABI 时才用）。
9. **句柄持有 runtime 与连接池**，重定向策略、cookie、本次连接会话都挂在句柄上；
   `rci_get` 每次新建并销毁句柄，所以它不跨请求保留任何东西（见 §11.3）。
10. **`version` 是服务端协议版本**，不是 profile 的能力标签：一个 h2/h3 profile
   连到只支持 HTTP/1.1 的服务端，返回的仍是 `"HTTP/1.1"`；判断 profile 是否带
   HTTP/3 配置要看 `rci_profile_info(name).has_http3`。

---

## 8. 验证你的接入是否正确

先跑离线自检（不依赖外网，仓库里已带两套封装的测试）：

```sh
# Python
python3 bindings/ffi/python/testserver.py 8765 &
python3 -m pytest bindings/ffi/python/tests -q     # 需要 pytest

# Java（发布归档里把 java/ 整体拿出来即可，Maven 会自己找依赖）
cd java
RCI_LIB=/path/to/lib/librust_curl_impersonate_ffi.so RCI_BASE=http://127.0.0.1:8765 \
  mvn -o test
# 想连真实 HTTP/3 再加 -Drci.h3=1（需要外网 UDP，quic.nginx.org 会间歇关流，
# 测试自己重试 6 次）
```

两套测试覆盖的内容一致（Python 20 条、Java 16 条）：ABI 版本、48 个预置、profile 元数据、一次性 GET、
二进制 body 十六进制解码、POST + 逐请求头、默认头覆盖/抑制、未知选项被拒、
未知 profile 被拒、连接失败转异常、默认不跟随重定向、`follow_safe` 拒绝环回
并记录 redirect、last_headers / wire_profile / activity、运行时注册指纹、
HTTP/3 不可用的报错，以及可选的 HTTP/3 真实请求。

再对真实回显做一次指纹校验：拿 `chrome150` 请求 `https://tls.peet.ws/api/all`，
回显里的 JA4 应为 `t13d1516h2_8daaf6152771_d8a2da3f94cd`，Akamai h2 指纹应为
`1:65536;2:0;4:6291456;6:262144|15597570|0|m,s,a,p`。对不上说明 profile 没生效。

实测输出（2026-11-26，本机构建）：

```text
abi version: 2                  48 presets, 339 selectable profiles
ja4: t13d1516h2_8daaf6152771_d8a2da3f94cd
akamai: 1:65536;2:0;4:6291456;6:262144|15597570|0|m,s,a,p
```

---

## 9. 版本与兼容

- `rci_version()` 是运行时 ABI 版本。两套现成封装（Python、Java）加载后都断言
  它 >= 2；将来 ABI 3 会新增函数并保持 2 的语义，所以 `>= 2` 的封装不需要改。
- 改签名/所有权规则要 bump `ABI_VERSION` 并重建 tag。CI 用 `nm -D` 比对头文件与
  导出表、用 `bindings/ffi/tests/abi.rs` 断言 JSON 形状、用
  `tools/gen_signatures.py --check` 断言 Java 声明与头文件一致；Python 封装与
  Java 封装的测试也在 CI 里跑，所以「文档与实现脱节」会被红。
- 封装作者想加一个新函数（例如 future 的 `rci_*`）：先改 `rci.h` 与 Rust 侧，
  再跑 `python3 tools/gen_signatures.py --check` 看缺失了哪条 Java 声明，按
  `--java` 的输出补上即可。Python 封装不用动——它读头文件。

---

## 10. 给 AI agent：可安装的 skill

上面的步骤对人可读，但 agent 容易在「哪个目标」「签名长什么样」「谁负责释放」
这三处靠猜。仓库 [rust-curl-impersonate-skills](https://github.com/crawler-requests/rust-curl-impersonate-skills)
把这三处变成可执行的东西：一个 `SKILL.md` 流程 + 四个脚本。

```sh
claude plugin marketplace add crawler-requests/rust-curl-impersonate-skills
claude plugin install rust-curl-impersonate-native@rust-curl-impersonate-skills
```

装上后 agent 能自己做这些事，且每一步都能被验证：

| 脚本 | 作用 |
|---|---|
| `fetch_library.py` | 按本机（含 musl/glibc 区分）或 `--target` 选 18 个目标之一，从 GitHub 下载（断点续传）、对 `SHA256SUMS` 校验、解包到 `rci/` |
| `verify_abi.py` | 15 项离线检查（17 个导出、ABI>=2、48 预置、`NULL` 句柄/字符串、错误路径）；加 `--echo` 再断言 JA4 与 Akamai h2 与抓包一致 |
| `gen_declarations.py` | 从 `rci.h` 生成 Java 接口、可编译的 cgo 声明块、ctypes `argtypes/restype`，不靠手抄 |
| `local_echo_server.py` | 离线回显服务，验证请求路径、头合并、重定向策略、二进制 body 解码 |

`assets/` 里还带两套现成封装（ctypes 的 `rci_bindings.py` 与 JNA 的 Maven 工程），
它们与本章源码同源。skill 的 `references/api.md` 就是 §2 的机器可读化版本，
`references/troubleshooting.md` 把常见故障映射到原因。

这个 skill 在 2026-11-27 用 `v0.3.0` 发布归档实测：下载在两次断连后续传成功、
校验通过、`verify_abi.py --echo` 取到 JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`，
自带 Python 封装 19 项、Java 封装 16 项测试全绿；并从 GitHub 远程 `plugin
marketplace add` + `plugin install` 走通。

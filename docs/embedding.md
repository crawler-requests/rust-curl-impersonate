# 把 rust-curl-impersonate 内嵌进其它语言

本库的指纹逻辑只有 Rust 这一份实现。其它语言通过一份 **C ABI 共享库**
（或静态库）使用它：一个 `.so` / `.dylib` / `.dll`，加一个 `rci.h`。

- 想直接用 Rust：[README](../README.md) 里的 `Client` / `Profile`。
- 想看完整函数语义：[bindings/ffi/README.md](../bindings/ffi/README.md)。
- 想加自己的指纹记录但不发版：[provider-protocol.md](provider-protocol.md)。

本文档回答两件事：**支持的 API 有哪些**，以及**每种语言怎么接进来**。
文中的每一段示例代码都在 `v0.3.0` 产物上实际跑通过。

---

## 1. 拿到库

从 [Releases](https://github.com/crawler-requests/rust-curl-impersonate/releases)
下载对应平台归档，解压后：

```
include/rci.h              C 头文件
lib/librust_curl_impersonate_ffi.so    动态库（.dylib / .dll）
lib/librust_curl_impersonate_ffi.a     静态库（Windows 上是 .lib）
python/demo.py             现成的 Python 绑定
USING_THIS_ARCHIVE.md      归档用法说明
README.md                  完整函数表
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
| 适用 | Python / Node / Java / PHP 等运行时加载 | iOS App、单文件 CLI、不想附带 .so 的场景 |
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

ABI 版本 **2**，`rci_version()` 返回它。共 **17 个函数**，全部 `extern "C"`。
v1 的全部签名和 JSON 字段在 v2 里保持不变。

### 2.1 库与 profile 查询

| 函数 | 返回 | 说明 |
|---|---|---|
| `uint32_t rci_version(void)` | `2` | ABI 版本 |
| `char *rci_targets(void)` | JSON 字符串数组 | 48 个 curl-impersonate 预设名 |
| `char *rci_profiles(void)` | JSON 字符串数组 | 48 个预设 + 指纹库全部记录名（339 个） |
| `char *rci_profile_info(const char *name)` | JSON 对象 | 单个 profile 的元数据 |

`rci_profile_info` 的对象字段：

```json
{
  "name": "chrome150",
  "wire": "chrome150",
  "family": "chrome",
  "platform": "",
  "fidelity": null,
  "deviation": null,
  "http1_only": false,
  "has_http3": true,
  "source": ""
}
```

- `wire`：实际发出的线路参数来自哪个预设（别名会指向基座）。
- `fidelity`：`"exact"` / `"close"` / `"partial"` / `null`（内置预设为 `null`）。
- `deviation`：抓包里发不出来的字段说明，没有则 `null`。
- `has_http3`：该 profile 有没有 QUIC 配置，决定 `rci_http3_get` 能否用。
- 未知名字返回 `{"error":"unknown profile <name>"}`。

### 2.2 创建与释放客户端

| 函数 | 说明 |
|---|---|
| `RciClient *rci_client_new(const char *profile)` | 默认设置（30 秒超时）。名字未知返回 `NULL`，原因见 `rci_last_error()` |
| `RciClient *rci_client_new_with_options(const char *profile, const char *options_json)` | 带选项；`NULL` 或 `"{}"` 表示默认 |
| `void rci_client_free(RciClient *h)` | 释放句柄，`NULL` 无害 |
| `char *rci_client_profile(RciClient *h)` | 这个句柄发出的是哪个预设的字节 |

`options_json` 的全部键（都可选，**未知键会报错**）：

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

- `proxy`：`http://`、`https://`、`socks5://`、`socks5h://`。
- `follow_redirects: false`：收到第一个响应就停（能看到 302 本身）。
- `follow_safe: true`：跟随重定向，但解析到环回/私网/链路本地地址时拒绝。
- `headers`：加到每个请求上；同名替换预设默认头，空值抑制该头。
- `split_cookies`：HTTP/2 里每个 cookie 一条 `Cookie` 头。
- `http1_only`：强制 HTTP/1.1。

### 2.3 发请求

| 函数 | 说明 |
|---|---|
| `char *rci_request(h, method, url, body, len)` | body 是字节缓冲，`len=0` 时可为 `NULL` |
| `char *rci_request_with(h, method, url, headers_json, body)` | headers 是 JSON `[["名","值"],…]`；body 是 NUL 结尾的 UTF-8 字符串 |
| `char *rci_get(profile, url)` | 一次性 GET：建客户端、发请求、释放 |
| `char *rci_http3_get(profile, addr, host, path)` | 走 HTTP/3；profile 必须有 QUIC 配置 |

**响应是一个 JSON 对象**：

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

- `version`：`"HTTP/1.1"` / `"HTTP/2.0"` / `"HTTP/3.0"`。
- `url`：经过重定向后的最终地址。
- `headers`：保持到达顺序的 `[名, 值]` 数组。
- `body_is_text: true` 时 `body` 是 UTF-8 文本；`false` 时 `body` 是**小写十六进制**，
  解成字节即可（这样二进制内容不会被截断或损坏）。
- 失败：`{"error":"..."}`。

`rci_http3_get` 的 `addr` 是 `"ip:port"`（也可以是主机名，会先解析），
`host` 是 SNI 与 `:authority`，`path` 是请求路径。HTTP/3 的响应体遵循与
`rci_request` 相同的文本/十六进制规则。

### 2.4 句柄内省

| 函数 | 返回 |
|---|---|
| `char *rci_client_last_headers(h)` | 最近一次响应的头，JSON `[名,值]` 数组；未发过请求时是 `[]` |
| `char *rci_client_activity(h)` | `{"cookies":["SET\t…"],"redirects":["302\t…"]}` |

### 2.5 运行时加指纹记录

| 函数 | 说明 |
|---|---|
| `char *rci_load_fingerprints(const char *json)` | 把一个库 schema 的 JSON 文档注册进当前进程 |

注册后新名字立刻能用于 `rci_client_new`；与内置记录同名时覆盖内置的那条（本进程内）。
文档先校验再接纳，坏的整份拒绝。返回 `"{}"` 表示成功。

### 2.6 内存与错误

| 函数 | 规则 |
|---|---|
| `char *…` 返回值 | **归库所有**，必须用 `rci_string_free()` 释放；两者都接受 `NULL` |
| `const char *rci_last_error(void)` | 本线程最近一次建句柄失败的原因；指针在下一次调用前有效，**不需要释放** |
| 返回 `NULL` 吗 | 返回 `char *` 的查询/请求函数**不返回 `NULL`**，出错时返回 `{"error":…}` JSON；只有 `rci_client_new*` 失败返回 `NULL` 句柄 |

---

## 3. 各语言接入

每个示例都在 `v0.3.0` 产物上跑通。路径按需替换。

### 3.1 C

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

### 3.2 C++

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

### 3.3 Python（ctypes）

归档里已有现成的 `python/demo.py`，它带一个 `Client` 类可直接复制。最小写法：

```python
import ctypes, json

lib = ctypes.CDLL("./lib/librust_curl_impersonate_ffi.so")
lib.rci_get.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.rci_get.restype = ctypes.c_void_p
lib.rci_string_free.argtypes = [ctypes.c_void_p]

p = lib.rci_get(b"chrome150", b"https://example.com")
reply = json.loads(ctypes.string_at(p).decode())
lib.rci_string_free(p)
print(reply["status"], reply["version"])
```

要点：

- `restype` 必须设成 `c_void_p`（不是 `c_char_p`），否则 ctypes 会复制并让指针失配。
- 二进制 body：`bytes.fromhex(reply["body"])` 当 `body_is_text` 为 `False`。

### 3.4 Node.js（koffi）

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

要点：返回值声明成 `void *`，koffi 就不会把它当字符串接管所有权。
`ffi-napi` 同理。

### 3.5 Go（cgo）

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

### 3.6 Java / Kotlin（JNA）

```java
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

public interface Rci extends Library {
    Rci INSTANCE = Native.load("./lib/librust_curl_impersonate_ffi.so", Rci.class);
    int rci_version();
    Pointer rci_get(String profile, String url);
    void rci_string_free(Pointer p);
}

public class Demo {
    public static void main(String[] a) {
        Rci r = Rci.INSTANCE;
        System.out.println("abi " + r.rci_version());
        Pointer p = r.rci_get("chrome150", "https://example.com");
        String json = p.getString(0);
        r.rci_string_free(p);
        System.out.println(json);
    }
}
```

依赖：`implementation 'net.java.dev.jna:jna:5.14.0'`。
返回类型用 `Pointer` 而不是 `String`，自己决定何时释放。

### 3.7 PHP（FFI，7.4+）

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

要点：PHP 的 `FFI::cdef` 解析不了 `rci.h` 里的中文注释，所以内联一份精简声明
（函数名与参数类型必须与 `rci.h` 一致）。

### 3.8 Swift / Kotlin(NDK) / C#

- **Swift（iOS/macOS）**：链接静态库 `.a`，在 bridging header 里
  `#import "rci.h"`。iOS 必须用 `.a`，App Store 不收随包动态库。
- **Kotlin / Java on Android**：`.a` 或 `.so` 都行；`.so` 放 `jniLibs/<abi>/`，
  NDK 侧 include `rci.h` 后用 JNI 包一层。Android 动态库运行时需要 NDK 的
  `libc++_shared.so`（静态库不需要）。
- **C#**：`[DllImport("rust_curl_impersonate_ffi")]` + `IntPtr` 返回值，
  再 `Marshal.PtrToStringAnsi`，最后 `rci_string_free`。

### 3.9 Rust 自身

不想要 C ABI 时直接依赖 crate：

```toml
[dependencies]
rust-curl-impersonate = { git = "https://github.com/crawler-requests/rust-curl-impersonate" }
```

---

## 4. 通用注意事项

1. **调用是阻塞的**。每个请求等响应才返回。**复用一个句柄**，不要每请求都
   `rci_get`（那会重建 runtime 和连接池）。
2. **线程**：句柄不是线程安全的，一个线程一个句柄；`rci_last_error` 是线程局部的。
3. **内存**：`char *` 返回值用 `rci_string_free`；句柄用 `rci_client_free`。
   两者都允许传 `NULL`。
4. **错误**：请求失败返回 `{"error":"…"}` 的 JSON，不是 `NULL`。只有
   `rci_client_new*` 失败返回 `NULL`，原因读 `rci_last_error()`。
5. **二进制响应**：`body_is_text == false` 时 `body` 是十六进制，别当文本用。
6. **HTTP/3 需要 QUIC 配置**：先用 `rci_profile_info(name).has_http3` 判断；
   没有的 profile 调 `rci_http3_get` 会返回 error，不会静默退回 HTTP/2。
7. **动态库加载路径**：Linux `rpath`/`LD_LIBRARY_PATH`，macOS
   `@rpath`/`DYLD_LIBRARY_PATH`，Windows 与 exe 同目录即可。

---

## 5. 验证你的接入是否正确

跑通后先做一次自检：拿 `chrome150` 对 `https://tls.peet.ws/api/all` 发一次请求，
回显里的 JA4 应该是 `t13d1516h2_8daaf6152771_d8a2da3f94cd`，Akamai h2 指纹是
`1:65536;2:0;4:6291456;6:262144|15597570|0|m,s,a,p`。对不上说明 profile 没生效。

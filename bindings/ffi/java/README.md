# Java 封装（JNA）

`rust-curl-impersonate` 的 C ABI 的 Java 封装。纯 JNA，不依赖 Jackson/Gson；
原生库在运行时加载，所以 jar 可以发布，`.so`/`.dylib`/`.dll` 跟应用一起分发。

## 构建与测试

```sh
mvn package                                             # 产出 target/*.jar
RCI_LIB=/path/to/lib/librust_curl_impersonate_ffi.so \
RCI_BASE=http://127.0.0.1:8765 mvn test                # 需要一个本地测试服务器
```

`RCI_BASE` 默认 `http://127.0.0.1:8765`，用归档里 `python/testserver.py 8765` 起。
`-Drci.h3=1` 追加一条真实 HTTP/3 用例（需要外网 UDP，会自己重试）。

## 使用

```java
try (RustCurlImpersonate.Client client = RustCurlImpersonate.client("chrome150")) {
    RustCurlImpersonate.Response reply = client.get("https://tls.peet.ws/api/all");
    System.out.println(reply.status() + " " + reply.version());
    System.out.println(reply.bodyText().substring(0, 200));
}

RustCurlImpersonate.profileInfo("go1.26").deviation();     // 元数据
RustCurlImpersonate.client("chrome150", new RustCurlImpersonate.Settings()
        .timeoutMs(10_000).header("accept-language", "zh-CN").followSafe(true));
```

## 库从哪来

`RciNative` 按以下顺序找原生库：

1. 系统属性 `rci.lib`（库文件，或归档的 `lib/` 目录）
2. 环境变量 `RCI_LIB`
3. classpath 资源 `/rci/<平台>/<库文件名>`（自己把原生库打进 jar 时用）
4. JNA 的 `jna.library.path` 与系统默认查找路径

## 约定（与 ABI 一致）

- `char *` 返回值归库所有：`RciLibrary` 里一律声明成 `Pointer`，读到文本后
  `rci_string_free`。声明成 `String` 会让 JNA 丢掉原始指针，再释放就崩。
- `const char *rci_last_error()` 不归调用方，声明成 `String` 是安全的。
- 句柄不是线程安全的：一个线程一个 `Client`。所有调用阻塞到响应到达。
- 失败是 `RciException`，消息就是库返回的 `{"error": ...}` 文本。
- `Response.content()` 在 `body_is_text == false` 时自动把十六进制解回字节。

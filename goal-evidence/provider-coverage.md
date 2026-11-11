# 数据/指纹 Provider 化覆盖度调查

目标：**"大部分的数据、指纹都可以重构为 Provider 机制"**。这份文档逐块盘点
仓库里会改变线上字节（或描述客户端）的硬编码数据，说明每块现在的去向、已经
Provider 化的程度，以及为什么剩下的保持现状或本来就是代码。

## 结论速览

| 数据块 | 行数 | 内容 | 状态 |
|---|---|---|---|
| `src/fingerprint/builtin.json` | 194 条记录 | 抓包指纹库（161 base + 33 aliases） | ✅ 已是 provider（`BuiltinProvider`） |
| `src/profile/behavior.rs` | 49 | 48 个预置的 `split_cookies` / `form_boundary` 表 | ✅ 可被 provider 记录覆盖；保留为 fallback |
| `src/fingerprint/mod.rs` 记录 schema | 941 | 记录字段 + TLS/HTTP2/HTTP3 解析 | ✅ 记录现在是**完整 profile 载体**（本轮补全） |
| `src/profile/generated.rs` | 5450 | 48 个 curl-impersonate 目标：TLS/HTTP2 set-tings、deviation、HTTP/3 | ⏸️ 维持生成表；新目标经 provider 记录表达 |
| `src/profile/spec.rs` | 606 | `ProfileSpec` 手工 profile 构建器 | ✅ 与 provider 记录同一套生成逻辑（共享 `policy`） |
| `src/profile/compress.rs` | 101 | 证书压缩名 → BoringSSL 对象 | ⚙️ 代码（映射逻辑），非数据 |
| `src/policy.rs` | 449 | settings/扩展/证书压缩/伪头/包号解析 | ⚙️ 解析逻辑，非数据；所有记录共用 |
| `src/form.rs` | 93 | WebKit/Firefox multipart 边界生成器 | ⚙️ 代码（生成规则），非数据 |
| `preset_family` / `preset_platform` | — | 48 个预置名的家族/平台推断 | ⚙️ 代码（命名规则），非数据 |

## 逐块说明

### 1. `builtin.json` → `BuiltinProvider`（✅ 完成）

194 条记录（161 base + 33 aliases）由 `tools/gen_fingerprints.py` 从
`tools/capture/raw/` 的真实抓包生成，经 `BuiltinProvider` 以 `PRIORITY_BUILTIN`(0)
注册为默认 provider。它只是 Provider 机制里的一个实现：`JsonProvider` /
`DirProvider` / `FnProvider` / `RemoteProvider` 与它完全同构，所以"内置库"与
"云端库/自定义库"之间没有代码分叉。

#### 1a. 最新版本记录：同样是真实浏览器抓的

库里的每条记录都来自真实客户端进程实际发出的 ClientHello，没有手写、改版本
号或复用旧抓包伪装新版本。比 curl-impersonate 更新的浏览器按来源抓：

- Chromium 157.0.8103.38：本机 Snap Chromium，`chromium_capture.py`；
- Chrome 158.0.8127.18 / 159.0.8144.0：Google 官方 Chrome for Testing 的
  Beta / Dev 通道构建，`chromium_capture.py <out> <binary>` 指定二进制；
- Firefox 158.0.1 / 159.0.1 / 160.0 / 161.0b1 / 162.0a1：Mozilla 官方 Snap
  的 stable / candidate / beta / edge 四个通道，逐通道 `snap refresh` 后抓包。

真实数据本身也说明了跨版本稳定性：Firefox 158–162 五版的 JA4 完全相同
（wire 结构确实没变），而 Chrome 158/159 相对 156/157 多了两个扩展
（`Unknown extension 4832` 与带真实 binder 的 `pre_shared_key`），说明盲目
沿用旧抓包改版本号会在 Chrome 上直接露馅。

线上验证见 `goal-evidence/real-versions-echo.txt`：Firefox 159–162 的 TLS
结构与 JA4 与抓包完全一致；Chrome 157/158/159 的差异只有 BoringSSL 发不出
的扩展（4832、51764）、pre_shared_key（需要缓存 ticket）与 ML-DSA 签名
算法，均已写入 `deviations`。

### 2. `behavior.rs` 48 目标行为表（✅ 可被 Provider 记录覆盖）

`split_cookies` 与 `form_boundary` 原来只有一张按 48 个预置名匹配的表，provider
记录无法表达 → 本轮给 `Fingerprint` 加 `split_cookies: Option<bool>` 与
`form_boundary: Option<String>` 字段，`Profile::split_cookies()` /
`Profile::form_boundary()` 的取值顺序：

1. 安装的记录（`install`/`load_json` 写入的 `StoredMeta`）；
2. provider 记录自带的字段；
3. `behavior` 表（48 个预置名的 fallback）。

`prepare.rs` 已改走 `profile.form_boundary()` / `profile.split_cookies()`。
因此云端/自定义 provider 现在可以**覆盖**内置预置的行为，或给全新名字配行为，
而不必改代码。测试：`a_provider_record_can_express_a_complete_browser_profile`、
`a_document_can_carry_http3_multipart_and_cookie_behavior`。

### 3. 记录 schema = 完整 profile 载体（✅ 本轮补全）

`Fingerprint` 原来只能表达 TLS ClientHello + HTTP/2 SETTINGS + headers，缺三块
浏览器行为：HTTP/3 输入、multipart 边界、cookie 拆分。本轮补上：

- `http3: Option<Http3Fingerprint>` — 19 个字段，与 `ProfileSpec` 的 `http3_*`
  构建器一一对应；cipher 缺省回退记录的 TLS ciphers；别名记录委托 base；
- `form_boundary: Option<String>`、`split_cookies: Option<bool>`；
- 注册期内联校验：非别名记录的 `emulation()` 与 `http3_profile()` 在注册时
  构建，坏文档当场被拒（新增测试覆盖缺 cipher 的 HTTP/3）。

现在任何 provider（内置/JSON/目录/闭包/云端）的一条记录就能表达一个完整浏览器
profile，不需要 `extends` 指向预置。`Fingerprint::install()` 也会把这三块写进
`StoredMeta`，安装后的 profile 行为一致。

### 4. `generated.rs` 48 目标表（✅ 可被 Provider 记录整体覆盖，生成表=默认值）

这 5450 行是 **Rust 代码**（`emulation()`/`http3()` 的 match 分发 + 逐目标常量
函数），由 `tools/gen_profiles.py` 从 curl-impersonate 源码生成，是 48 个预置的
内置实现。它们不是"可替换的加载数据"，而是这个 crate 的公开 API 承诺
（`chrome150` 永远可用）——但**同一套 Provider 机制可以覆盖它们**：provider 记录
与预置重名（如 `chrome150`）时，`Profile::find` 返回的 `emulation()`/HTTP/3/
behavior 全部来自该记录（同名遮蔽，优先级规则不变），卸载后恢复 generated.rs
原定义。`tests/providers.rs` 的 `a_provider_record_can_override_a_builtin_preset`
验证了这一闭环。因此 generated.rs 的角色是"默认内置实现"，不是"唯一权威；
新版本浏览器/客户端完全走 provider 记录表达（demo：`cloud_chrome_full`），发版
后若想固化，`ProfileSpec::install` / `Fingerprint::install` 即可转成新记录。

### 5. 代码 vs 数据（⚙️ 保持代码）

- `compress.rs` / `policy.rs`：同名/规则 → BoringSSL 对象与解析函数，是所有记录
  **共用**的实现层。provider 记录只写名字（`"zlib,brotli"`），不重复逻辑；
- `form.rs`：WebKit/Firefox 边界的**生成规则**。数据面只有 `form_boundary` 字段
  一个字符串，「webkit/firefox → 边界形状」是实现细节；
- `preset_family`/`preset_platform`：按名字推断家族/平台的命名规则，仅服务于 48
  个预置名，provider 记录自带 `family`/`platform` 字段，不依赖它们。

## 演示

`goal-evidence/cloud-library.json` 新增 `cloud_chrome_full`：一条**不依赖任何预置**
的完整 profile 记录（TLS + HTTP/2 + headers + `form_boundary: webkit` +
`split_cookies: true` + HTTP/3 全参数），`examples/cloud_provider.rs` 用
`Client::new` 解析并打印 HTTP/3 SETTINGS 数、initial packet、boundary、cookie
拆分——证据见 `goal-evidence/cloud-provider.txt`。

## 测试

- `tests/providers.rs` 12 → 15：`loading_or_refreshing_a_provider_does_not_block_lookups`
  （注册/刷新 load 均不持注册表锁，阻塞的 load 期间 `find`/`providers()` 即时返回；
  坏 HTTP/3 记录注册被拒）、`a_provider_record_can_express_a_complete_browser_profile`
  （provider 记录携带 HTTP/3 + behavior）、`a_provider_record_can_override_a_builtin_preset`
  （预设同名覆盖 + 卸载恢复）；
- `tests/fingerprints.rs`：`a_document_can_carry_http3_multipart_and_cookie_behavior`
  （`load_json` 安装的完整记录 + 48 预置行为表回归断言），以及内置库
  161 条抓包记录与 33 个别名都可构建 `Client`。
- 全量 `cargo test`：**88 tests 全绿**（`tests/providers.rs` 15、`tests/fingerprints.rs` 19）。

## 协议文档与完整示例

- `docs/provider-protocol.md`：扩展契约规范——trait 四方法、生命周期保证、优先级/
  遮蔽、记录字段全表、三种数据源接入（内嵌文件 / 远端 ETag+304 / 自定义协议）。
- `examples/custom_provider.rs`：手写 `FingerprintProvider` 的自定义数据源示例
  （不依赖任何内置 provider，演示"实现协议即可扩展"），`cargo run --example
  custom_provider` 可跑。
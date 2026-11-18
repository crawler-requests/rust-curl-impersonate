# Chrome 扩展位的持续监控

Chrome 的 ClientHello 扩展一直在变。要做到“第一时间知道有新扩展”，需要盯住
两个来源，本仓库各有一个脚本处理。

## 一、有哪些来源，为什么是这两个

| 来源 | 覆盖什么 | 更新节律 | 脚本 |
|---|---|---|---|
| **IANA TLS ExtensionType 注册表** | 所有走标准流程登记的扩展位（含 RFC 与私有使用区） | 每个记录带 `updated` 日期，RFC 发布即更新 | `tools/watch_extensions.py` |
| **BoringSSL `tls1.h`**（vendored 副本） | Chromium 自己实现、不走 IANA 的扩展（4832、30032 等） | 随 BoringSSL 提交更新 | 同上 |

为什么不是别的来源：

- **Chromium 源码**（`net/ssl/`、`SSL_set_server_padding_request`）能让新扩展第一次
  出现，但 googlesource 在本网络下经常连不上，且 diff 噪声大。BoringSSL 头文件是
  它的下位信号：Chromium 要发一个扩展，先得在 BoringSSL 里写出来。
- **Chrome for Testing 的版本列表**（`last-known-good-versions.json`）只告诉你
  有新版本，不告诉你扩展变了；它更适合用来触发“重新抓包”，不适合发现新扩展位。

## 二、怎么用

```bash
python3 -I tools/watch_extensions.py           # 报告
python3 -I tools/watch_extensions.py --update  # 同时更新基线
```

输出示例（有新增时）：

```
IANA: 104 records, 1 new or changed
BoringSSL: 33 ids, 0 not in the baseline

New or changed extension ids:
  1234    iana          some_new_extension   2026-11-20
```

基线在 `goal-evidence/extension-watch-baseline.json`。没有变化时输出
`Nothing new since the baseline.`，适合放进 cron 里当静默检查。

## 三、发现新扩展之后做什么

1. **确认 Chrome 真的发了它**：抓一次当前 Chrome 的 ClientHello
   （`tools/capture/chromium_capture.py`，用 Chrome for Testing 的最新构建），看新 id
   是否出现。IANA 登记 ≠ Chrome 使用。
2. **判断 BoringSSL 能否表达**：
   - 头文件里已有 `TLSEXT_TYPE_*` 并带 `add_clienthello` → 直接映射；
   - 没有 → 在 `scripts/boringssl/chrome4832.patch` 里加一个开关，参照现有的
     `SSL_CTX_set_server_padding_request` / `SSL_CTX_set_channel_id_offer` /
     `SSL_CTX_set_force_padding_len` 三例；
   - 需要调用方提供数据（如 trust anchors 的标识符列表）→ 记录字段 + builder 方法。
3. **补抓包**：把新版本的 Chrome 抓包放进 `tools/capture/raw/`，
   `python3 -I tools/gen_fingerprints.py` 重新生成库，
   `python3 -I tools/extension_registry.py` 刷新扩展登记表。
4. **验证**：`cargo test --workspace` + 线上 `echo <记录名> tls.peet.ws` 对比 JA4。

## 四、接入定时检查

三种方式，按环境选：

```bash
# 1) cron：每天 09:00 检查一次，有输出才发邮件
0 9 * * * cd /path/to/repo && python3 -I tools/watch_extensions.py | \
  grep -q "Nothing new" || python3 -I tools/watch_extensions.py | mail -s "Chrome extensions changed" you@example.com

# 2) Claude Code 的 /loop：让会话自己定期跑
/loop 1d python3 -I tools/watch_extensions.py

# 3) CI：定时任务里跑，有变化就开 issue
```

## 五、当前的覆盖面

`tools/extension_registry.py` 生成的
[`extension-registry.md`](extension-registry.md) 是当前快照：Chrome 抓包里出现过的
扩展位、BoringSSL 认识但 Chrome 没用的扩展位，逐条标明本仓库怎么发（native /
patch / cache / unsupported）。

2026-11-18 的快照结论：

- Chrome 抓包里出现过 **22** 个扩展位，**没有一个是 unsupported**；
- 其中 18 个原生可发，3 个需要 BoringSSL 补丁（4832、30032、padding 21），
  1 个（pre_shared_key）走会话缓存（登记表 `native` 计数含 BoringSSL 认识的
  全部 id，因此是 30 而非 18）；
- BoringSSL 另外认识 30 个 Chrome 没用到的扩展位，登记表一并列出，方便未来比对。

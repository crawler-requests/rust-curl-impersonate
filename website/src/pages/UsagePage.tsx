import { Link } from "react-router-dom";
import { CodeBlock, Comment, Str } from "../components/CodeBlock";
import { AreaMark } from "../components/icons";
import { PresetPicker } from "../components/PresetPicker";

const REPO = "https://github.com/crawler-requests/rust-curl-impersonate";

export function UsagePage() {
  return (
    <>
      <section className="hero hero--compact">
        <div className="hero__eyebrow">用法</div>
        <h1 className="hero__title">
          选一个名字，
          <br />
          剩下的<b>交给它</b>。
        </h1>
        <p className="hero__lede">
          Profile::find 接受 48 个 curl-impersonate 预设里的任意一个，也接受指纹库里按家族或版本命名的记录名。
          TLS、HTTP/2、HTTP/3 与 QUIC 参数都从预设或记录里读出来，调用方不必再拼一遍。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="presets" />
          安装
        </span>
        <h2 className="section__title">两种引入方式，都不需要手写补丁</h2>
        <p className="section__lede">
          本仓库把改过的 wreq / quinn 源码直接放在 <code>vendor/</code> 里，所以依赖它就像依赖普通 crate，
          不需要自己配 <code>[patch.crates-io]</code>。命令行工具不在本仓库；需要非 Rust 调用时用下面的 C ABI。
        </p>
        <CodeBlock>
          <Comment>{"# 方式一：作为 git 依赖（推荐，直接拿到最新提交）\n"}</Comment>
          {"[dependencies]\nrust-curl-impersonate = { git = "}
          <Str>{`"${REPO}"`}</Str>
          {" }\n\n"}
          <Comment>{"# 方式二：下载预编译的 C ABI 共享库（给 Python / Node / Go / Java / C++）\n"}</Comment>
          <Comment>{"# 每个归档都带 rci.h、librust_curl_impersonate_ffi.* 和 python/demo.py\n"}</Comment>
          {"# 见 https://github.com/crawler-requests/rust-curl-impersonate/releases\n"}
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="presets" />
          最小例子
        </span>
        <h2 className="section__title">创建客户端，发一个请求</h2>
        <CodeBlock>
          {"use rust_curl_impersonate::{Client, Profile};\n\n"}
          {"# async fn run() -> rust_curl_impersonate::Result<()> {\n"}
          {"let profile = Profile::find("}
          <Str>"chrome150"</Str>
          {").expect("}
          <Str>"chrome150 是一个内置目标"</Str>
          {");\nlet client = Client::new(profile)?;\nlet response = client.get("}
          <Str>"https://example.com"</Str>
          {").send().await?;\nprintln!("}
          <Str>"{}"</Str>
          {", response.status());\n# Ok(())\n# }\n"}
        </CodeBlock>
        <p className="section__lede">
          记录名同样可以直接选：<code>Profile::find("android_okhttp13")</code>、
          <code>Profile::find("python")</code>（即 <code>python3.12_requests</code>）。
          它们和 48 个预设一样，不需要安装步骤。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="http3" />
          HTTP/3
        </span>
        <h2 className="section__title">带 QUIC 配置的预设走 HTTP/3</h2>
        <p className="section__lede">
          HTTP/3 走 QUIC，需要自己解析目标地址再交给端点；<code>http3_endpoint()</code> 取到的端点已经带好
          该预设的 SETTINGS、传输参数与初始包号。没有 QUIC 配置的预设（如 Firefox 153–155）会在
          <code>http3_endpoint()</code> 处返回错误，而不是悄悄退回 HTTP/2。
        </p>
        <CodeBlock>
          {"let profile = Profile::find("}
          <Str>"chrome150"</Str>
          {").expect("}
          <Str>"chrome150 有 QUIC 配置"</Str>
          {");\nlet client = Client::new(profile)?;\nlet endpoint = client.http3_endpoint()?;\n\n"}
          <Comment>{"// 需要 `use std::net::ToSocketAddrs;`\n"}</Comment>
          <Comment>{"// quic 走 UDP；这里只需地址\n"}</Comment>
          {"let addr = (host, 443u16).to_socket_addrs()\\n    .expect("}
          <Str>"resolve"</Str>
          {").find(|a| a.is_ipv4()).unwrap();\\nlet response = endpoint.get(addr, host, "}
          <Str>"/"</Str>
          {").await?;\\nprintln!("}
          <Str>"{}"</Str>
          {", response.body.len());   "}
          <Comment>{"// H3Response { headers, body }\n"}</Comment>
          <Comment>{"// 想让 Client 自己处理代理时用它，它走同一个端点\n"}</Comment>
          {"let response = client.http3_get(addr, host, "}
          <Str>"/"</Str>
          {").await?;\\n"}
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="proxy" />
          请求头与 Cookie
        </span>
        <h2 className="section__title">默认头按预设顺序发，同名的由调用方替换</h2>
        <CodeBlock>
          <Comment>{"// 同名头替换默认头；空值抑制该头；其余默认头保留\n"}</Comment>
          {"let response = client.get("}
          <Str>"https://example.com"</Str>
          {")?.header("}
          <Str>"accept-language"</Str>
          {", "}
          <Str>"zh-CN,zh;q=0.9"</Str>
          {").header("}
          <Str>"x-dnt"</Str>
          {", "}
          <Str>""</Str>
          {").send().await?;\n\n"}
          <Comment>{"// Cookie：HTTP/1.1 合成一条头，HTTP/2 与 HTTP/3 按 cookie 拆开\n"}</Comment>
          {"let response = client.request_cookies("}
          <Str>"GET"</Str>
          {", "}
          <Str>"https://example.com"</Str>
          {", "}
          <Str>"a=1; b=2"</Str>
          {").send().await?;\n"}
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="proxy" />
          代理与 DNS
        </span>
        <h2 className="section__title">HTTP、HTTPS、SOCKS5 三种代理</h2>
        <CodeBlock>
          {"let client = Client::builder(Profile::find("}
          <Str>"chrome150"</Str>
          {")?)?\n    .proxy_url("}
          <Str>"socks5://127.0.0.1:1080"</Str>
          {")?\n    .build()?;\n\n"}
          <Comment>{"// 代理能解析域名时，客户端不再自己去查 HTTPS 记录\n"}</Comment>
          {"let response = client.get("}
          <Str>"https://example.com"</Str>
          {").send().await?;\n"}
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="websocket" />
          WebSocket
        </span>
        <h2 className="section__title">deflate 扩展与压缩负载</h2>
        <CodeBlock>
          <Comment>{"// 建立带 TLS 指纹的 WebSocket 连接\n"}</Comment>
          {"let socket = client.websocket("}
          <Str>"wss://example.com/chat"</Str>
          {").send().await?;\n\n"}
          <Comment>{"// 想发 permessage-deflate 扩展时，用它建连；对端接受后自动压缩 / 解压\n"}</Comment>
          {"let upgrade = client.websocket_deflate("}
          <Str>"wss://example.com/chat"</Str>
          {").send().await?;   "}
          <Comment>{"// 没连 zlib 时 websocket_deflate 会 panic，改用 try_ 版本返回错误\n"}</Comment>
          {"let upgrade = client.try_websocket_deflate("}
          <Str>"wss://example.com/chat"</Str>
          {", zlib_linked)?\n    .send().await?;\n"}
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="override" />
          覆盖预设字段
        </span>
        <h2 className="section__title">不改生成的预设源码，也能改字段</h2>
        <CodeBlock>
          {"let client = Client::builder(Profile::find("}
          <Str>"chrome150"</Str>
          {")?)?\n    .sigalgs("}
          <Str>"ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256"</Str>
          {")?   "}
          <Comment>{"// 只覆盖签名算法，其余保持预设值\n"}</Comment>
          {"\n    .build()?;\n\n"}
          <Comment>{"// 也可以登记一个新名字，沿用另一个预设的线路设置\n"}</Comment>
          {"Profile::register("}
          <Str>"my-chrome"</Str>
          {", Profile::find("}
          <Str>"chrome150"</Str>
          {")?)?;\n"}
        </CodeBlock>
      </section>

      <PresetPicker />

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="fork" />
          该选哪一个
        </span>
        <h2 className="section__title">按你面对的服务端挑</h2>
        <p className="section__lede">
          目标不同，合适的名字也不同。下面是最常见的几种情况，每一种都指向已经抓包验证过的记录。
        </p>
        <div className="issue-grid">
          <div className="issue-card">
            <div className="issue-card__title">要过浏览器风控</div>
            <div className="issue-card__body">
              用浏览器预设：chrome150、firefox155、ios_safari26。
              它们来自官方构建，扩展顺序、GREASE 与 ALPS 都按真实浏览器发。
            </div>
          </div>
          <div className="issue-card">
            <div className="issue-card__title">服务端在认「哪个 Go / Python 版本」</div>
            <div className="issue-card__body">
              用运行时的记录：go1.26、python3.12_requests、node22_http2。
              同一语言的不同版本经常只差一个扩展，选错版本会被看出来。
            </div>
          </div>
          <div className="issue-card">
            <div className="issue-card__title">请求要从 Android 应用里发出</div>
            <div className="issue-card__body">
              用 Android 记录：android_okhttp13、android_conscrypt13、
              android_webview125。按系统版本和内置栈选，不是随便挑一个。
            </div>
          </div>
          <div className="issue-card">
            <div className="issue-card__title">要同时走 HTTP/3</div>
            <div className="issue-card__body">
              选带 QUIC 配置的预设：chrome145、146、150，firefox147。
              其他预设没有 HTTP/3 指纹，要求只走 HTTP/3 会失败。
            </div>
          </div>
        </div>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="abi" />
          非 Rust 调用
        </span>
        <h2 className="section__title">C ABI：17 个函数，够写一个可用封装</h2>
        <p className="section__lede">
          <code>bindings/ffi</code> 导出一份 C ABI 共享库，任何能调 C 的语言都能用。除了发请求，
          它还能列出可选 profile、读元数据、带选项建客户端、逐请求加头、回传二进制 body、
          发 HTTP/3、以及在运行时注册指纹记录。下载页面上的每个归档都带 <code>rci.h</code> 和一个现成的
          <code>python/demo.py</code>。
        </p>
        <CodeBlock>
          <Comment>{"# Python：解压归档后，把 RCI_LIB 指向 lib/ 里的共享库\n"}</Comment>
          {"python3 python/demo.py chrome150 https://tls.peet.ws/api/all\n\n"}
          <Comment>{"# 其它语言：include rci.h，链接同一个库\n"}</Comment>
          {"rci_client_new(profile) -> rci_request(handle, method, url, body, len) -> rci_string_free(reply)\n"}
        </CodeBlock>
        <p className="section__lede">
          完整函数表见归档里的 <code>README.md</code>；封装注意事项（阻塞调用、字符串所有权、错误 JSON）
          也写在那里。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">下一步</span>
        <h2 className="section__title">想知道它有多准，去看证据</h2>
        <p className="section__lede">
          库里每一条记录都来自真实抓包，审计脚本会从抓包里重算 JA4，对不上就让 CI 失败。
          想了解哪些字段发不出来，<Link className="inline-link" to="/limits">边界页</Link>逐项列出了原因。
        </p>
      </section>
    </>
  );
}

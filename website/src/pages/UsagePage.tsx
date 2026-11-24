import { CodeBlock, Comment, Str } from "../components/CodeBlock";

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
        <span className="section__kicker">最小例子</span>
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
      </section>

      <section className="section">
        <span className="section__kicker">HTTP/3</span>
        <h2 className="section__title">带 QUIC 配置的预设走 HTTP/3</h2>
        <p className="section__lede">
          预设带 HTTP/3 指纹时用 http3_get；http3_endpoint 是这条发送路径绑定的端点，
          HTTP/3 SETTINGS、传输参数、初始包号都在其中。协商到 HTTP/3 之后，
          headers_after_negotiation 使用该预设单独的 HTTP/3 默认头；回退时仍用普通默认头。
        </p>
        <CodeBlock>
          {"let client = Client::new(Profile::find("}
          <Str>"chrome150"</Str>
          {")?)?;\nlet endpoint = client.http3_endpoint()?;\nlet response = client.http3_get("}
          <Str>"https://example.com"</Str>
          {").send().await?;\n\n"}
          <Comment>{"// Firefox 153–155 没有单独的 HTTP/3 指纹，要求只走 HTTP/3 会失败\n"}</Comment>
          {"let response = client.http3_get("}
          <Str>"https://example.com"</Str>
          {").http3_only(true).send().await;\n"}
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">请求头与 Cookie</span>
        <h2 className="section__title">默认头按预设顺序发，同名的由调用方替换</h2>
        <CodeBlock>
          <Comment>{"// 同名头替换默认头；空值抑制该头；其余默认头保留\n"}</Comment>
          {"let response = client.get("}
          <Str>"https://example.com"</Str>
          {")?\n    .header("}
          <Str>"accept-language"</Str>
          {", "}
          <Str>"zh-CN,zh;q=0.9"</Str>
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
        <span className="section__kicker">代理与 DNS</span>
        <h2 className="section__title">HTTP、HTTPS、SOCKS5 三种代理</h2>
        <CodeBlock>
          {"let client = Client::builder(Profile::find("}
          <Str>"chrome150"</Str>
          {")?)?\n    .proxy_url("}
          <Str>"socks5://127.0.0.1:1080"</Str>
          {")?\n    .build()?;\n\n"}
          <Comment>{"// HTTP/3 走 SOCKS5 时改用 UDP ASSOCIATE（命令字节 0x03）\n"}</Comment>
          {"let response = client.http3_get("}
          <Str>"https://example.com"</Str>
          {").send().await?;\n"}
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">WebSocket</span>
        <h2 className="section__title">deflate 扩展与压缩负载</h2>
        <CodeBlock>
          {"let upgrade = client.websocket_deflate("}
          <Str>"wss://example.com/chat"</Str>
          {").send().await?;\nlet ws = upgrade.accepted_codec()?;   "}
          <Comment>{"// 文本与二进制自动压缩 / 解压\n"}</Comment>
          {"\n"}
          <Comment>{"// 没有链接 zlib 时返回 WsError::NotBuilt，且不发这个扩展\n"}</Comment>
          {"let upgrade = client.try_websocket_deflate("}
          <Str>"wss://example.com/chat"</Str>
          {").send().await?;\n"}
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">覆盖预设字段</span>
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

      <section className="section">
        <span className="section__kicker">C ABI</span>
        <h2 className="section__title">给非 Rust 调用方</h2>
        <CodeBlock>
          <Comment>{"// bindings/ffi 提供共享库；演示脚本在 bindings/ffi/python/demo.py\n"}</Comment>
          {"python3 bindings/ffi/python/demo.py chrome150 https://example.com/\n"}
        </CodeBlock>
      </section>
    </>
  );
}

import { Link } from "react-router-dom";
import { CodeBlock, Comment, Str } from "../components/CodeBlock";
import { totals } from "../data/library";

// The landing page: what this is, the problem it removes, and where to read
// next. Details live on their own pages.

const ROUTES = [
  {
    to: "/problem",
    kicker: "解决什么问题",
    title: "为什么需要一个库来做这件事",
    body: "指纹不是「换个 User-Agent」：cipher 顺序、扩展顺序、GREASE、ECH、ALPS 决定了服务端看到的客户端。rustls 发不出这些。",
  },
  {
    to: "/android",
    kicker: "Android",
    title: "每种库、每个版本都实测",
    body: "OkHttp、Conscrypt、Cronet、WebView，覆盖 Android 7.0 到 14，每条记录都在真实运行时上复现过。",
  },
  {
    to: "/library",
    kicker: "指纹库",
    title: "242 条记录，全部来自抓包",
    body: "浏览器、各语言运行时、Android 与 iOS 应用。可按名称、客户端、JA4 搜索，也可只看逐字节一致的那些。",
  },
  {
    to: "/usage",
    kicker: "用法",
    title: "选一个名字，发出请求",
    body: "Profile::find 接受预设名或记录名；TLS、HTTP/2、HTTP/3 与 QUIC 参数都从预设里读出来。",
  },
  {
    to: "/evidence",
    kicker: "可信度",
    title: "没有一条记录是写出来的",
    body: "审计脚本从抓包里重新算 JA4，对不上就让 CI 失败。标为 close 的记录写明哪一项发不出来。",
  },
];

export function HomePage() {
  return (
    <>
      <section className="hero">
        <div className="hero__eyebrow">Rust · BoringSSL · 开箱即用</div>
        <h1 className="hero__title">
          curl-impersonate 的 Rust 实现，
          <br />
          把<b>真实客户端的握手</b>搬到代码里。
        </h1>
        <p className="hero__lede">
          rustls 不暴露 cipher 顺序、扩展顺序、GREASE、ECH、ALPS 与证书压缩，
          所以真正的指纹只能建在 BoringSSL 上。本库以 wreq 为传输层，
          在上面重写 curl 那一层：选择预设、套用 TLS、HTTP/2 与 HTTP/3 参数、发出请求。
        </p>
        <div className="hero__stats">
          <div>
            <div className="stat__value">{totals.records}</div>
            <div className="stat__label">条抓包记录</div>
          </div>
          <div>
            <div className="stat__value">{totals.families}</div>
            <div className="stat__label">个客户端家族</div>
          </div>
          <div>
            <div className="stat__value">{totals.android}</div>
            <div className="stat__label">条 Android 记录</div>
          </div>
          <div>
            <div className="stat__value">{totals.presets}</div>
            <div className="stat__label">个 curl-impersonate 预设</div>
          </div>
        </div>
        <div className="hero__actions">
          <Link className="cta" to="/usage">
            开始使用
          </Link>
          <Link className="cta cta--ghost" to="/problem">
            解决什么问题
          </Link>
        </div>
      </section>

      <section className="section">
        <span className="section__kicker">用一行代码选择客户端</span>
        <h2 className="section__title">预设名与记录名，都接受</h2>
        <CodeBlock>
          <Comment>{"// 浏览器预设\n"}</Comment>
          {"let profile = "}
          <Str>"chrome150"</Str>
          {";\nlet client = Client::new(Profile::find(profile)?)?;\nlet response = client.get("}
          <Str>"https://example.com"</Str>
          {").send().await?;\n\n"}
          <Comment>{"// 指纹库里按家族命名的记录名\n"}</Comment>
          {"let client = Client::new(Profile::find("}
          <Str>"android_okhttp13"</Str>
          {")?)?;\nlet client = Client::new(Profile::find("}
          <Str>"python"</Str>
          {")?)?;   "}
          <Comment>{"// 即 python3.12_requests\n"}</Comment>
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">继续阅读</span>
        <h2 className="section__title">按主题展开</h2>
        <div className="route-grid">
          {ROUTES.map((route) => (
            <Link className="route-card" key={route.to} to={route.to}>
              <span className="route-card__kicker">{route.kicker}</span>
              <span className="route-card__title">{route.title}</span>
              <span className="route-card__body">{route.body}</span>
            </Link>
          ))}
        </div>
      </section>
    </>
  );
}

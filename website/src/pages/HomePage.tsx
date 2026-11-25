import { Link } from "react-router-dom";
import { CodeBlock, Comment, Str } from "../components/CodeBlock";
import { totals } from "../data/library";
import { FAMILY_PAGES } from "../data/families";
import { familyIcon } from "../components/icons";
import { Reveal } from "../components/Reveal";
import { HandshakeAnatomy } from "../components/HandshakeAnatomy";
import { Faq } from "../components/Faq";

// The landing page: what this is, the problem it removes, and where to read
// next. Details live on their own pages.

const REPO = "https://github.com/crawler-requests/rust-curl-impersonate";
const RELEASES = `${REPO}/releases`;
const LATEST_VERSION = "v0.2.0";

const ROUTES = [
  {
    to: "/problem",
    kicker: "解决什么问题",
    title: "为什么需要一个库来做这件事",
    body: "指纹不是「换个 User-Agent」：cipher 顺序、扩展顺序、GREASE、ECH、ALPS 决定了服务端看到的客户端。rustls 发不出这些。",
  },
  {
    to: "/clients",
    kicker: "客户端",
    title: "六类客户端，各有各的握手",
    body: "Chrome、Firefox、Safari、iOS、Android 与各语言运行时。选一族进去，看它为什么与别人不一样、有哪些版本可挑。",
  },
  {
    to: "/library",
    kicker: "指纹库",
    title: `${totals.records} 条记录，全部来自抓包`,
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
  {
    to: "/limits",
    kicker: "边界",
    title: "发不出来的东西写在明处",
    body: "ML-DSA、扩展 4832、真实 ECH、X448 与 pre_shared_key：哪些有补丁、哪些做不到，逐项列出。",
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
            <div className="stat__value">{totals.presets}</div>
            <div className="stat__label">个 curl-impersonate 预设</div>
          </div>
          <div>
            <div className="stat__value">{totals.families}</div>
            <div className="stat__label">个客户端家族</div>
          </div>
          <div>
            <div className="stat__value">{totals.exact}</div>
            <div className="stat__label">条逐字节一致</div>
          </div>
          <div>
            <div className="stat__value">9</div>
            <div className="stat__label">个平台预编译</div>
          </div>
          <div>
            <div className="stat__value">17</div>
            <div className="stat__label">个 C ABI 函数</div>
          </div>
        </div>
        <div className="hero__actions">
          <Link className="cta" to="/usage">
            开始使用
          </Link>
          <a className="cta cta--ghost" href={RELEASES} target="_blank" rel="noreferrer noopener">
            下载预编译库
          </a>
        </div>
        <p className="hero__install">
          在 Rust 里直接加一行依赖；其它语言从 Release 下载 9 个平台的共享库（
          <span className="mono">{LATEST_VERSION}</span>）：
        </p>
        <CodeBlock>
          <Comment>{"# Rust：直接加 git 依赖，不需要 [patch.crates-io]\n"}</Comment>
          {"rust-curl-impersonate = { git = "}
          <Str>{`"${REPO}"`}</Str>
          {" }\n\n"}
          <Comment>{"# 或：下载带 rci.h 与 python/demo.py 的 C ABI 共享库\n"}</Comment>
          <Str>{RELEASES}</Str>
          {"\n"}
        </CodeBlock>
      </section>

      <Reveal>
        <section className="section">
          <span className="section__kicker">用一行代码选择客户端</span>
        <h2 className="section__title">预设名与记录名，都接受</h2>
        <CodeBlock>
          <Comment>{"// 浏览器预设\n"}</Comment>
          {"let profile = Profile::find("}
          <Str>"chrome150"</Str>
          {").expect("}
          <Str>"已知目标"</Str>
          {");\nlet client = Client::new(profile)?;\nlet response = client.get("}
          <Str>"https://example.com"</Str>
          {").send().await?;\n\n"}
          <Comment>{"// 指纹库里按家族命名的记录名，同样不需要安装步骤\n"}</Comment>
          {"let client = Client::new(Profile::find("}
          <Str>"android_okhttp13"</Str>
          {").expect("}
          <Str>"记录存在"</Str>
          {"))?;\nlet client = Client::new(Profile::find("}
          <Str>"python"</Str>
          {").expect("}
          <Str>"即 python3.12_requests"</Str>
          {"))?;\n"}
        </CodeBlock>
      </section>
      </Reveal>

      <Reveal>
        <section className="section">
          <span className="section__kicker">不止 Rust</span>
        <h2 className="section__title">一份 C ABI，九种语言的起点</h2>
        <p className="section__lede">
          指纹逻辑只有 Rust 这一份实现。其它语言的封装都走同一个 C ABI 共享库——每个 Release
          归档里已经放好了 <code>rci.h</code> 和一个能直接跑的 <code>python/demo.py</code>，
          复制过去改就行，不用自己从零写 FFI。
        </p>
        <div className="lang-grid">
          {[
            ["Python", "demo.py 现成可改"],
            ["Node.js", "koffi / ffi-napi"],
            ["Go", "cgo"],
            ["Java / Kotlin", "JNA / Panama"],
            ["C / C++", "#include rci.h"],
            ["C#", "P/Invoke"],
            ["Ruby", "Fiddle"],
            ["PHP", "FFI"],
            ["Swift / Dart", "FFI 或 Rust 直接依赖"],
          ].map(([lang, how]) => (
            <div className="lang-card" key={lang}>
              <span className="lang-card__name">{lang}</span>
              <span className="lang-card__how">{how}</span>
            </div>
          ))}
        </div>
        <p className="section__lede">
          17 个导出函数覆盖：列出与查询 profile、带选项建客户端（超时/代理/默认头/重定向）、
          逐请求加头、二进制安全的响应、HTTP/3、请求活动记录、运行时注册指纹。
          完整表见 <Link className="inline-link" to="/usage">用法页</Link>。
        </p>
      </section>
      </Reveal>

      <Reveal>
        <HandshakeAnatomy
          kicker="先在浏览器里看一眼"
          title="一条 ClientHello 长什么样"
          lede="挑一个客户端，看它真正发出去的 cipher、扩展与密钥共享。这些值不是说明书上的参数，而是某次握手被抓包记下来的原样。"
        />
      </Reveal>

      <Reveal delay={90}>
        <section className="section">
          <span className="section__kicker">一眼看懂支持哪些客户端</span>
        <h2 className="section__title">浏览器、运行时、移动端，各有各的记录</h2>
        <p className="section__lede">
          每组都是抓包得到的真实握手，不是一个参数表。选一个名字就用那一组的线路参数，
          名称和版本对不上会被服务端看出来。
        </p>
        <div className="support-grid">
          {FAMILY_PAGES.map((page) => (
            <Link key={page.key} to={page.path} className="support-card">
              <span className="support-card__icon">{familyIcon(page.members[0])}</span>
              <span className="support-card__title">{page.nav}</span>
              <span className="support-card__body">{page.lede}</span>
            </Link>
          ))}
        </div>
      </section>
      </Reveal>

      <Reveal>
        <Faq />
      </Reveal>

      <Reveal delay={90}>
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
      </Reveal>
    </>
  );
}

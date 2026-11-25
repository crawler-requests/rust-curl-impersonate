import { CodeBlock, Comment, Str } from "../components/CodeBlock";
import { totals } from "../data/library";
import { FingerprintLeak } from "../components/FingerprintLeak";
import { Ja4Breakdown } from "../components/Ja4Breakdown";

// The page the site exists for: what problem the library removes.

export function ProblemPage() {
  return (
    <>
      <section className="hero hero--compact">
        <div className="hero__eyebrow">解决什么问题</div>
        <h1 className="hero__title">
          服务端看到的不是你的代码，
          <br />
          是你的<b>握手</b>。
        </h1>
        <p className="hero__lede">
          「换个 User-Agent」从来不够。TLS 握手里的 cipher 顺序、扩展顺序、
          GREASE、ECH、ALPS、证书压缩、签名算法顺序，加在一起才是服务端判定
          客户端的依据。这些东西由一个 TLS 实现决定，不由调用方决定。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">问题一</span>
        <h2 className="section__title">rustls 发不出浏览器的握手</h2>
        <p className="section__lede">
          rustls 的 API 是刻意收窄的：它不接受 cipher 顺序、扩展顺序、
          GREASE 值、ECH GREASE、ALPS、delegated credentials 与证书压缩列表。
          这些恰好是 JA3 / JA4 / Akamai / peetprint 用来区分客户端的东西。
          写死在 rustls 里的握手，因此只能"看起来像"某个浏览器，一被抓包就能看出不同。
        </p>
        <div className="compare">
          <div className="compare__col compare__col--bad">
            <div className="compare__title">只改 User-Agent</div>
            <div className="compare__row">TCP / TLS 握手：一个库的默认形态</div>
            <div className="compare__row">cipher 顺序：库自己决定</div>
            <div className="compare__row">扩展顺序：固定，不可选</div>
            <div className="compare__row">GREASE：没有</div>
            <div className="compare__row">ECH / ALPS：没有</div>
            <div className="compare__verdict">抓包即暴露</div>
          </div>
          <div className="compare__col compare__col--good">
            <div className="compare__title">本库</div>
            <div className="compare__row">TLS 握手：BoringSSL，按预设逐项设置</div>
            <div className="compare__row">cipher 顺序：含 TLS 1.3 的先后</div>
            <div className="compare__row">扩展顺序：可设，Chromium 还能每次重排</div>
            <div className="compare__row">GREASE：cipher / group / version / key share</div>
            <div className="compare__row">ECH GREASE、ALPS、证书压缩：可设</div>
            <div className="compare__verdict">与抓包一致</div>
          </div>
        </div>
      </section>

      <FingerprintLeak />

      <section className="section">
        <span className="section__kicker">问题二</span>
        <h2 className="section__title">知道了参数，也未必知道真实的值</h2>
        <p className="section__lede">
          一个浏览器版本、一个库版本到底发什么，只有抓包知道。
          网上流传的 fingerprint 列表经常漏掉顺序、GREASE 位置和 padding 规则，
          而这些细节会直接改变 JA4 的哈希。本库把"这条记录从哪次握手来"写进数据里，
          而不是靠文档推断。
        </p>
        <div className="fact-list">
          <div className="fact">
            <span className="fact__num">{totals.records}</span>
            <span className="fact__text">
              条记录，每条都指向 <code className="mono">tools/capture/raw/</code> 下的一次真实抓包
            </span>
          </div>
          <div className="fact">
            <span className="fact__num">{totals.android}</span>
            <span className="fact__text">
              条 Android 记录，在真机、容器或模拟器上复现过同一个 ClientHello
            </span>
          </div>
          <div className="fact">
            <span className="fact__num">{totals.presets}</span>
            <span className="fact__text">
              个 curl-impersonate 预设全部可用，含 Chrome 150–152、Firefox 153–155 等上游没有的
            </span>
          </div>
        </div>
      </section>

      <Ja4Breakdown />

      <section className="section">
        <span className="section__kicker">问题三</span>
        <h2 className="section__title">指纹只有 TLS 一半，HTTP/2 与 HTTP/3 也在看</h2>
        <p className="section__lede">
          Akamai 指纹读的是 HTTP/2 的 SETTINGS 值、顺序、伪头顺序、窗口更新与优先级；
          HTTP/3 还会读 QUIC 的传输参数与初始包号。只把 TLS 调对，HTTP 层照样露馅。
        </p>
        <CodeBlock>
          <Comment>{"// 预设不只是 TLS：HTTP/2 与 HTTP/3 字段一起带\n"}</Comment>
          {"let client = Client::new(Profile::find("}
          <Str>"chrome150"</Str>
          {").expect("}
          <Str>"已知目标"</Str>
          {"))?;\n\n"}
          <Comment>{"// HTTP/3：SETTINGS、传输参数、初始包号都来自预设\n"}</Comment>
          {"let endpoint = client.http3_endpoint()?;\nlet response = endpoint.get(addr, host, "}
          <Str>"/"</Str>
          {").await?;\n\n"}
          <Comment>{"// 预设没写伪头顺序时，不会自己补一个\n"}</Comment>
          {"assert!(client.prepared().pseudo_order().is_none());\n"}
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">问题四</span>
        <h2 className="section__title">上游预设之外的客户端也要能选</h2>
        <p className="section__lede">
          curl-impersonate 的 48 个预设覆盖主流浏览器。但实际遇到的是各种语言运行时、
          各版本 Android、iOS 应用、定制库。这些握手不在上游的列表里，
          要么自己抓包，要么只能靠猜。本库内置了这些记录，也允许在运行时加载更多。
        </p>
        <div className="fact-list">
          <div className="fact">
            <span className="fact__num">{totals.families}</span>
            <span className="fact__text">
              个客户端家族：Chrome、Firefox、Safari、iOS、Android、Go、Python、Node、PHP、Ruby、.NET、Bun、Deno、Dart、Erlang……
            </span>
          </div>
          <div className="fact">
            <span className="fact__num">{totals.aliases}</span>
            <span className="fact__text">
              个别名，例如 golang、python、curl、android、okhttp_android，指向同一份线路参数
            </span>
          </div>
        </div>
        <CodeBlock>
          <Comment>{"// 内置之外，运行时还能加\n"}</Comment>
          {"register_provider(JsonProvider::from_path("}
          <Str>"team-records.json"</Str>
          {"));\nlet client = Client::new(Profile::find("}
          <Str>"our-internal-app"</Str>
          {")?)?;\n"}
        </CodeBlock>
      </section>

      <section className="section">
        <span className="section__kicker">结论</span>
        <h2 className="section__title">本库做的事</h2>
        <ul className="plain-list">
          <li>保留 curl-impersonate 的 BoringSSL 部分——真正能拼出浏览器 ClientHello 的那一半。</li>
          <li>用 wreq 做传输层，在上面重写 curl 那一层：选预设、套 TLS、设 HTTP/2 与 HTTP/3、发请求。</li>
          <li>把真实客户端的抓包做成可查询的记录，而不是散落在文档里的参数表。</li>
          <li>每条记录都能被审计脚本从抓包重算验证，不能验证的就不进库。</li>
        </ul>
      </section>
    </>
  );
}

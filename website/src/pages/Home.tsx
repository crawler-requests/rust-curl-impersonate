import { androidRecordCount, familySummary, records } from "../data/library";
import { AndroidLibraries } from "../components/AndroidLibraries";
import { CodeBlock, Comment, Str } from "../components/CodeBlock";
import { LibraryExplorer } from "../components/LibraryExplorer";

// One page: what the project is, how it is used, the Android coverage, then
// the whole library. The Android section comes first because that is the part
// this site exists to describe in detail.

export function Home() {
  const maxFamily = familySummary[0]?.count ?? 1;
  return (
    <>
      <header className="site-header">
        <div className="site-header__inner">
          <span className="wordmark">
            <span className="wordmark__dot" />
            rust-curl-impersonate
          </span>
          <nav className="site-header__links">
            <a href="#android">Android</a>
            <a href="#library">指纹库</a>
            <a href="#usage">用法</a>
            <a href="https://github.com/crawler-requests/rust-curl-impersonate">
              GitHub
            </a>
          </nav>
        </div>
      </header>

      <div className="page">
        <section className="hero">
          <div className="hero__eyebrow">Rust · BoringSSL · 开箱即用</div>
          <h1 className="hero__title">
            curl-impersonate 的 Rust 实现，
            <br />
            把<b>真实客户端的握手</b>搬到代码里。
          </h1>
          <p className="hero__lede">
            rustls 不会暴露 cipher 顺序、扩展顺序、GREASE、ECH、ALPS 与证书压缩，
            所以真正的指纹只能建在 BoringSSL 上。本库以 wreq 为传输层，
            在上面重写 curl 那一层：选择预设、套用 TLS、HTTP/2 与 HTTP/3 参数、发出请求。
          </p>
          <div className="hero__stats">
            <div>
              <div className="stat__value">{records.length}</div>
              <div className="stat__label">条抓包记录</div>
            </div>
            <div>
              <div className="stat__value">{familySummary.length}</div>
              <div className="stat__label">个客户端家族</div>
            </div>
            <div>
              <div className="stat__value">{androidRecordCount}</div>
              <div className="stat__label">条 Android 记录</div>
            </div>
            <div>
              <div className="stat__value">48</div>
              <div className="stat__label">个 curl-impersonate 预设</div>
            </div>
          </div>
        </section>

        <section className="section" id="usage">
          <span className="section__kicker">用法</span>
          <h2 className="section__title">一行选择预设，剩下的交给它</h2>
          <p className="section__lede">
            <code className="mono">Profile::find</code> 接受任意一个内置名字，
            也接受指纹库里按家族命名的记录名。TLS、HTTP/2、HTTP/3 与 QUIC 参数
            都从预设或记录里读出来，不需要调用方再拼一遍。
          </p>
          <CodeBlock>
            <Comment>{"// 浏览器预设\n"}</Comment>
            {"let profile = "}
            <Str>"chrome150"</Str>
            {";\nlet client = Client::new(Profile::find(profile)?)?;\nlet response = client.get("}
            <Str>"https://example.com"</Str>
            {").send().await?;\n\n"}
            <Comment>{"// 指纹库里的客户端家族\n"}</Comment>
            {"let client = Client::new(Profile::find("}
            <Str>"go1.26"</Str>
            {")?)?;\nlet client = Client::new(Profile::find("}
            <Str>"python"</Str>
            {")?)?;   "}
            <Comment>{"// 即 python3.12_requests\n"}</Comment>
            {"let client = Client::new(Profile::find("}
            <Str>"android_okhttp13"</Str>
            {")?)?;\n"}
          </CodeBlock>
        </section>

        <AndroidLibraries />

        <LibraryExplorer />

        <section className="section" id="families">
          <span className="section__kicker">覆盖范围</span>
          <h2 className="section__title">按家族看记录数量</h2>
          <p className="section__lede">
            浏览器进程实测、官方 Docker 镜像抓到的各语言运行时、
            tls-client 的 ClientHello 定义并实测、uTLS 的旧版本定义，
            以及 Android 与 iOS 上的真实应用。
          </p>
          <div className="family-grid">
            {familySummary.map((family) => (
              <div className="family-tile" key={family.key}>
                <div className="family-tile__name">{family.label}</div>
                <div className="family-tile__count">{family.count} 条记录</div>
                <div
                  className="family-tile__bar"
                  style={{
                    background: family.tint,
                    width: `${Math.max(18, (family.count / maxFamily) * 100)}%`,
                  }}
                />
              </div>
            ))}
          </div>
        </section>

        <section className="section">
          <span className="section__kicker">为什么可信</span>
          <h2 className="section__title">没有一条记录是写出来的</h2>
          <p className="section__lede">
            每条记录都指向 <code className="mono">tools/capture/raw/</code> 下的一次抓包。
            审计脚本会从抓包里重新算出 JA4，与记录里的哈希比对；
            记录声称的头或 HTTP/2 参数只要有一项不在抓包里，构建就会失败。
            保真度标为 <span className="badge-close">close</span> 的记录，
            会在 deviations 里写明哪一项 BoringSSL 发不出来。
          </p>
          <div className="trust-grid">
            <div className="trust-item">
              <div className="trust-item__title">每条记录都有抓包</div>
              <div className="trust-item__body">
                {records.length} 条记录全部指向一次真实握手，没有一条是照着参数拼出来的。
              </div>
            </div>
            <div className="trust-item">
              <div className="trust-item__title">哈希可以重算</div>
              <div className="trust-item__body">
                审计从抓包里重新算 JA4 的 b、c 段，与记录里的值比对；
                对不上就让 CI 失败。
              </div>
            </div>
            <div className="trust-item">
              <div className="trust-item__title">Android 逐字节复核</div>
              <div className="trust-item__body">
                Android 的每条记录都在真机、容器或模拟器上复现过同一个 ClientHello。
              </div>
            </div>
          </div>
          <CodeBlock>
            <Comment>{"$ python3 -I tools/audit_provenance.py\n"}</Comment>
            {"242 base records, 0 problems\n202 stored JA4s recomputed from their capture,\n233 records checked against their capture\n"}
          </CodeBlock>
        </section>

        <footer className="site-footer">
          MIT License · 与 lexiforest/curl-impersonate 的 48 个预设对齐 ·
          <a href="https://github.com/crawler-requests/rust-curl-impersonate">
            {" "}
            GitHub
          </a>
        </footer>
      </div>
    </>
  );
}

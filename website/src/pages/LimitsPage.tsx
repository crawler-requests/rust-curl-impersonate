import { Link } from "react-router-dom";
import { CodeBlock, Comment } from "../components/CodeBlock";
import { AreaMark } from "../components/icons";

// The honest edge of the library: what BoringSSL cannot put on the wire, and
// what the crate does about it. Everything here is from README's "传输层表达
// 不了的字段" and "BoringSSL 补丁" sections.

const FIELDS = [
  {
    field: "mldsa44 / 65 / 87",
    kind: "签名算法",
    state: "补丁后能发",
    body: "Chrome 150 起的预设把这三个放在签名算法列表开头。标准 BoringSSL 拒绝这三个名字；scripts/boringssl/chrome4832.patch 给它们加了 code point。",
  },
  {
    field: "扩展 4832",
    kind: "私有扩展",
    state: "补丁后能发",
    body: "Chromium 的 server padding request，上游 BoringSSL 没有这个扩展。补丁把它作为 SSL_CTX_set_server_padding_request 的开关。",
  },
  {
    field: "signature_algorithms 的 GREASE",
    kind: "GREASE",
    state: "补丁后能发",
    body: "BoringSSL 默认拒绝未知 code point，补丁让 GREASE 也覆盖签名算法列表。",
  },
  {
    field: "真实 ECH",
    kind: "扩展 65037",
    state: "只能发 GREASE",
    body: "没有 ECHConfig 时发的是随机长度的占位。真正加密的 ClientHello 需要先拿到服务端的 ECH 公钥，本库不替调用方去取。",
  },
  {
    field: "X448 / ffdhe4096+",
    kind: "命名组",
    state: "发不出",
    body: "BoringSSL 的组表里没有这些大 DH 组。Python、Go 的记录因此在 groups 一项上只能 close 或 partial。",
  },
  {
    field: "pre_shared_key",
    kind: "扩展 41",
    state: "续连时才发",
    body: "第一次连接没有缓存 ticket，就不会带这一项。要它出现，得先用同一个客户端接一次，再从缓存里续连。",
  },
  {
    field: "curl 的非 HTTP 协议",
    kind: "协议族",
    state: "不在范围内",
    body: "本库只做 HTTP/1.1、HTTP/2、HTTP/3 与 WebSocket。FTP、SMTP、文件上传协议不在这里，也不打算加。",
  },
  {
    field: "HTTP/2 的 PRIORITY 标志",
    kind: "帧标志",
    state: "不发",
    body: "h2 crate 不写 HEADERS 的 PRIORITY 标志。Akamai 指纹不受影响，因为它读的是 SETTINGS、窗口与伪头顺序，不是这个标志位。",
  },
];

export function LimitsPage() {
  return (
    <>
      <section className="hero hero--compact">
        <div className="hero__eyebrow">边界</div>
        <h1 className="hero__title">
          发不出来的东西，
          <br />
          写在这里，而不是<b>假装发得出来</b>。
        </h1>
        <p className="hero__lede">
          一个库最不可信的地方，是它只告诉你成功的那部分。这一页列出传输层层面确实做不到的字段、
          本库怎么绕、以及哪些是补丁也补不上的。每条记录里的 deviations 就是从这里来的。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="limits" />
          字段表
        </span>
        <h2 className="section__title">八个发不出或只能近似发出的字段</h2>
        <p className="section__lede">
          「补丁后能发」指的是编译时带上 scripts/boringssl/chrome4832.patch；
          不带补丁也能编译，只是那几项自动不发，JA4 会与抓包差一位。
        </p>
        <div className="limits__table-wrap">
          <table className="limits__table">
            <thead>
              <tr>
                <th>字段</th>
                <th>类别</th>
                <th>状态</th>
                <th>说明</th>
              </tr>
            </thead>
            <tbody>
              {FIELDS.map((entry) => (
                <tr key={entry.field}>
                  <td className="mono">{entry.field}</td>
                  <td>{entry.kind}</td>
                  <td>
                    <span
                      className={`limits__state ${
                        entry.state === "补丁后能发"
                          ? "limits__state--ok"
                          : entry.state === "发不出" || entry.state === "不在范围内"
                            ? "limits__state--no"
                            : "limits__state--part"
                      }`}
                    >
                      {entry.state}
                    </span>
                  </td>
                  <td className="limits__body">{entry.body}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="audit" />
          补丁怎么用
        </span>
        <h2 className="section__title">打不打补丁，是编译选项</h2>
        <CodeBlock>
          <Comment>{"# 生成带补丁的 BoringSSL 源码树，并导出构建变量\n"}</Comment>
          {"scripts/boringssl/build.sh\n"}
          {"eval \"$(scripts/boringssl/build.sh --env)\"\n"}
          {"cargo build --release\n\n"}
          <Comment>{"// 不打补丁：cfg(chrome_4832) 关闭，扩展 4832 不发送，其余不变\n"}</Comment>
          {"# cargo build --release\n"}
        </CodeBlock>
        <p className="section__lede" style={{ marginTop: 22 }}>
          补丁只加三项能力，约五十行：扩展 4832、ML-DSA 的三个 code point、签名算法列表上的 GREASE。
          打完补丁后 <span className="mono">echo chrome160</span> 对 tls.peet.ws 的回显与抓包逐字节一致：
          <span className="mono"> t13d1518h2_8daaf6152771_4980c97edce0</span>。
          详情在 <a href="https://github.com/crawler-requests/rust-curl-impersonate#boringssl-补丁与真实浏览器完全一致的指纹" target="_blank" rel="noreferrer noopener">README</a>。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="evidence" />
          这些限制反映在记录里
        </span>
        <h2 className="section__title">保真度不是评分，是清单</h2>
        <p className="section__lede">
          一条记录标 close，说明抓包里那几项它发不出来，差额写进了 deviations；
          标 partial 说明差额多到形状已经明显不同。想知道具体缺什么，
          <Link to="/evidence">可信度</Link> 页按种类列出了全部 88 条。
        </p>
        <div className="hero__actions">
          <Link className="cta" to="/evidence">
            看审计输出
          </Link>
          <Link className="cta cta--ghost" to="/library">
            按保真度筛记录
          </Link>
        </div>
      </section>
    </>
  );
}

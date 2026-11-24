import { CodeBlock, Comment } from "../components/CodeBlock";
import { records, totals } from "../data/library";

// What makes the records trustworthy: the audit, the fidelity vocabulary, and
// the limits stated plainly.

const CLAIMS = [
  {
    title: "每条记录都有抓包",
    body: `{totals.records} 条记录全部指向 tools/capture/raw/ 下的一次真实握手，没有一条是照着参数拼出来的。`,
  },
  {
    title: "哈希可以重算",
    body: "审计从抓包里重新算 JA4 的 b、c 段，与记录里的值比对；对不上就让 CI 失败。",
  },
  {
    title: "记录字段不得超出抓包",
    body: "记录里声称的每一个请求头、每一项 HTTP/2 SETTINGS，都必须在抓包里找到；找不到就判为编造。",
  },
  {
    title: "Android 逐字节复核",
    body: `${totals.android} 条 Android 记录都在真机、容器或模拟器上复现过同一个 ClientHello，三段哈希相等。`,
  },
  {
    title: "发不出来的写下来",
    body: "BoringSSL 不支持的 cipher、组或签名算法，记录在 deviations 里，保真度因此不是 exact。",
  },
  {
    title: "抓包本身也修正",
    body: "tls.peet.ws 把扩展计数写成一位数（t12d129）、把 0x0808 也命名为 ed25519，这些在线路的 raw 里修正并注明。",
  },
];

const LIMITS = [
  "ML-DSA 签名算法（mldsa44/65/87）不在 BoringSSL 里，Chrome 150 起的预设会丢掉这三项；其余签名算法不丢。",
  "X448 与 ffdhe 组 BoringSSL 不支持，因此部分 Python、Go 记录只能是 close 或 partial。",
  "Firefox 153–155 没有单独的 HTTP/3 指纹；要求只走 HTTP/3 时会失败，不会编一个出来。",
  "少数抓包来自本地 socket 而非服务端，JA4 只有 a 段；这些记录单独列出。",
  "presets 里没写 HTTP/2 伪头顺序的（如 Chrome 150），不会被补上一个顺序。",
];

export function EvidencePage() {
  const exact = records.filter((r) => r.fidelity === "exact").length;
  const close = records.filter((r) => r.fidelity === "close").length;
  const partial = records.filter((r) => r.fidelity === "partial").length;

  return (
    <>
      <section className="hero hero--compact">
        <div className="hero__eyebrow">可信度</div>
        <h1 className="hero__title">
          没有一条记录
          <br />
          是<b>写出来的</b>。
        </h1>
        <p className="hero__lede">
          一条错记录比没有记录更糟：它让请求看起来像某个客户端，却在服务端露出破绽。
          所以本库对每条记录都做机械化检查，并把检查不通过的东西明确标出来。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">六条检查</span>
        <h2 className="section__title">审计做了什么</h2>
        <div className="issue-grid">
          {CLAIMS.map((claim) => (
            <div className="issue-card" key={claim.title}>
              <div className="issue-card__title">{claim.title}</div>
              <div className="issue-card__body">{claim.body}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="section">
        <span className="section__kicker">当前结果</span>
        <h2 className="section__title">审计输出</h2>
        <CodeBlock>
          <Comment>{"$ python3 -I tools/audit_provenance.py\n"}</Comment>
          {"233 base records, 0 problems\n202 stored JA4s recomputed from their capture,\n233 records checked against their capture\n31 records came from a local socket, not a server\n"}
        </CodeBlock>
        <div className="fact-list" style={{ marginTop: 22 }}>
          <div className="fact">
            <span className="fact__num">{exact}</span>
            <span className="fact__text">条 exact：与抓包逐字节一致</span>
          </div>
          <div className="fact">
            <span className="fact__num">{close}</span>
            <span className="fact__text">条 close：少数项发不出来，已注明</span>
          </div>
          <div className="fact">
            <span className="fact__num">{partial}</span>
            <span className="fact__text">条 partial：丢的项较多，形状明显不同</span>
          </div>
        </div>
      </section>

      <section className="section">
        <span className="section__kicker">边界</span>
        <h2 className="section__title">明确写在文档里的限制</h2>
        <ul className="plain-list">
          {LIMITS.map((limit) => (
            <li key={limit}>{limit}</li>
          ))}
        </ul>
      </section>

      <section className="section">
        <span className="section__kicker">证据在哪里</span>
        <h2 className="section__title">仓库里可以直接查</h2>
        <CodeBlock>
          <Comment>{"tools/capture/raw/            每条记录的抓包\n"}</Comment>
          <Comment>{"goal-evidence/               复现步骤与逐条结果\n"}</Comment>
          <Comment>{"goal-evidence/android-matrix/record-evidence.txt\n"}</Comment>
          <Comment>{"                             27 条 Android 记录各自的证据\n"}</Comment>
          {""}
        </CodeBlock>
      </section>
    </>
  );
}

import { Link } from "react-router-dom";
import { AreaMark } from "../components/icons";
import { CodeBlock, Comment } from "../components/CodeBlock";
import { echoRuns, segments, verdict } from "../data/echo";

// The page that answers "how do you know it works?" with the actual runs: each
// record impersonated, echoed back by tls.peet.ws, compared field by field with
// the capture it came from.

const VERDICT_TEXT = {
  identical: { label: "逐字节一致", tone: "ok", note: "JA4 与扩展集合都与抓包相同。" },
  ciphers: {
    label: "cipher 与扩展一致",
    tone: "part",
    note: "cipher 与扩展的哈希相同，只有签名算法段不同。",
  },
  differs: { label: "有差异", tone: "no", note: "JA4 不同，需要看差异来自哪里。" },
} as const;

export function VerificationPage() {
  const identical = echoRuns.filter((run) => verdict(run) === "identical").length;

  return (
    <>
      <section className="hero hero--compact">
        <div className="hero__eyebrow">线上实测</div>
        <h1 className="hero__title">
          不是「应该一致」，
          <br />
          是<b>跑出来才知道</b>。
        </h1>
        <p className="hero__lede">
          每条新记录都会用编译好的库真实发一次请求，让 tls.peet.ws 把收到的 ClientHello 回显回来，
          再与当初的抓包逐字段比对。下面就是最近一轮的结果：
          {echoRuns.length} 次运行里 {identical} 次与抓包逐字节一致，其余差异都能在记录的 deviations 里找到出处。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="evidence" />
          这一轮
        </span>
        <h2 className="section__title">每条记录一次真实请求</h2>
        <div className="verify__list">
          {echoRuns.map((run) => {
            const state = verdict(run);
            const info = VERDICT_TEXT[state];
            return (
              <article className="verify__row" key={run.name}>
                <div className="verify__head">
                  <span className="verify__name mono">{run.name}</span>
                  <span className={`verify__badge verify__badge--${info.tone}`}>{info.label}</span>
                  <span className="verify__http mono">
                    {run.status} · {run.httpVersion}
                  </span>
                </div>
                <div className="verify__segments">
                  {segments(run).map((part, index) => (
                    <span
                      key={`${run.name}-${index}`}
                      className={`verify__seg${part.same ? " is-same" : ""}`}
                      title={`抓包 ${part.capture} / 回显 ${part.echo}`}
                    >
                      <span className="verify__seg-label">
                        {index === 0 ? "协议" : index === 1 ? "cipher+扩展" : "签名算法"}
                      </span>
                      <span className="mono">{part.same ? part.capture : part.echo}</span>
                      {part.same ? null : (
                        <span className="verify__seg-was mono">抓包 {part.capture}</span>
                      )}
                    </span>
                  ))}
                </div>
                <div className="verify__meta">
                  <span>
                    扩展 {run.captureExtensions} → {run.echoExtensions}
                  </span>
                  {run.missing.length > 0 ? (
                    <span className="verify__missing">少发 {run.missing.join("、")}</span>
                  ) : null}
                  {run.extra.length > 0 ? (
                    <span className="verify__missing">多发 {run.extra.join("、")}</span>
                  ) : null}
                  <span>{info.note}</span>

                </div>
              </article>
            );
          })}
        </div>
        <p className="verify__conclusion">
          四组 Firefox 记录与抓包完全一致。四组 Chrome 记录只差签名算法一段：
          Chrome 156 起的签名算法列表以 ML-DSA 与 GREASE 打头，标准 BoringSSL 发不出来；
          chrome158 与 159 的抓包本身是续连会话，还多一个 pre_shared_key。
          这些都不在本次实测之外——它们正是每条记录 deviations 里写着的东西。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">
          <AreaMark icon="audit" />
          怎么跑
        </span>
        <h2 className="section__title">一条命令，一次回显</h2>
        <CodeBlock>
          <Comment>{"# 用编译好的库发一次请求，tls.peet.ws 回显服务端看到的握手\n"}</Comment>
          {"cargo build --release --example echo\n"}
          {"target/release/examples/echo chrome160 https://tls.peet.ws/api/all\n\n"}
          <Comment>{"# 逐字段对比回显与抓包：两个目录，第三个参数是记录名前缀\n"}</Comment>
          {"python3 -I tools/compare_echo.py tools/capture/raw goal-evidence/echo-latest chrome\n"}
        </CodeBlock>
        <p className="section__lede" style={{ marginTop: 22 }}>
          回显里也能看到 HTTP/2 的 Akamai 指纹与请求头顺序。想核对某一条记录里怎么发，
          可以回到 <Link to="/library">指纹库</Link> 按名字找它，或看{" "}
          <Link to="/limits">边界</Link> 页里哪些字段是补丁后才发得出来的。
        </p>
      </section>
    </>
  );
}

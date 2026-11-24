import { useMemo, useState } from "react";
import { Segmented } from "antd";
import type { Handshake } from "../data/handshakes";
import { cipherKind, handshakeFor } from "../data/handshakes";
import { extensionLabel } from "../data/extensions";
import { familyIcon } from "./icons";
import { FileSearchOutlined } from "@ant-design/icons";

// One ClientHello, laid out the way a server reads it. Switching the record
// redraws every part of it: the cipher list shortens or grows, the extension
// order moves, key shares appear or not. Nothing is illustrative — each pane
// reads straight from the capture the record names.

const PICKS = [
  { key: "chrome158", label: "Chrome 158" },
  { key: "firefox160", label: "Firefox 160" },
  { key: "ios_safari26", label: "iOS Safari 26" },
  { key: "android_okhttp13", label: "OkHttp 4.12" },
  { key: "go1.26", label: "Go 1.26" },
  { key: "python3.12_requests", label: "Python requests" },
];

const CIPHER_LEGEND: Record<string, string> = {
  tls13: "TLS 1.3",
  chacha: "ChaCha20",
  gcm: "AES-GCM",
  cbc: "CBC",
  dhe: "DHE",
  rsa: "RSA 密钥交换",
};

function fact(label: string, value: string | boolean) {
  if (typeof value === "boolean") {
    return { label, on: value, text: value ? "带" : "不带" };
  }
  return { label, on: null, text: value };
}

export interface AnatomyPick {
  key: string;
  label: string;
}

// The family pages pass their own records; the client directory uses the
// six-family set so a reader can compare across stacks in one place.
export function HandshakeAnatomy({
  picks = PICKS,
  initial,
  kicker = "一条 ClientHello 拆开来看",
  title = "服务端读的每一段，都来自真实抓包",
  lede = "下面每一栏都是某条记录里的真实值：cipher 列表、扩展顺序、命名组、签名算法，以及它开口说的第一个 HTTP/2 帧。换一条记录，整块内容都会跟着换。",
}: {
  picks?: AnatomyPick[];
  initial?: string;
  kicker?: string;
  title?: string;
  lede?: string;
} = {}) {
  const available = useMemo(() => picks.filter((pick) => handshakeFor(pick.key)), [picks]);
  const [selected, setSelected] = useState(initial ?? available[0]?.key ?? "");
  // Once the panel is showing the props' first pick, it follows the props
  // when they change: navigating from /chrome to /runtimes keeps the same
  // component mounted, and a stale selection would show Chrome's hello under
  // a runtimes heading.
  const record: Handshake | undefined =
    handshakeFor(selected) && available.some((pick) => pick.key === selected)
      ? handshakeFor(selected)
      : handshakeFor(available[0]?.key ?? "");

  const [copied, setCopied] = useState(false);

  if (!record || available.length === 0) return null;

  // The record names the capture it was read from:
  // "tls.peet.ws capture, tools/capture/raw/chrome158.json".
  const sourcePath = record.source.match(/tools\/capture\/raw\/[^\s,]+/)?.[0] ?? "";

  const facts = [
    fact("GREASE", record.grease),
    fact("ECH GREASE", record.echGrease),
    fact("ALPS", record.alps),
    fact("扩展重排", record.permuteExtensions),
    fact("证书压缩", record.certCompression.length ? record.certCompression.join(" / ") : false),
    fact("delegated creds", record.delegatedCredentials > 0),
  ];

  const copyOrder = async () => {
    try {
      await navigator.clipboard.writeText(record.extensionOrder.join("-"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // A blocked clipboard leaves the value on screen, which is enough.
    }
  };

  return (
    <section className="section anatomy" id="anatomy">
      <div className="section__head">
        <span className="section__kicker">{kicker}</span>
        <h2 className="section__title">{title}</h2>
        <p className="section__lede anatomy__lede">{lede}</p>
      </div>

      {available.length > 1 ? (
        <Segmented
          className="anatomy__switch"
          value={selected}
          onChange={(value) => setSelected(String(value))}
          options={available.map((pick) => ({ label: pick.label, value: pick.key }))}
        />
      ) : null}

      <div className="anatomy__record">
        <span className="anatomy__icon">{familyIcon(record.family)}</span>
        <div className="anatomy__record-text">
          <span className="anatomy__record-name mono">{record.name}</span>
          <span className="anatomy__record-meta">
            {record.client}
            {record.version ? ` · ${record.version}` : ""} · {record.platform}
          </span>
        </div>
        <button type="button" className="anatomy__copy" onClick={copyOrder}>
          {copied ? "已复制扩展顺序" : "复制扩展顺序"}
        </button>
      </div>
      {sourcePath ? (
        <a
          className="anatomy__source"
          href={`https://github.com/crawler-requests/rust-curl-impersonate/blob/main/${sourcePath}`}
          target="_blank"
          rel="noreferrer noopener"
        >
          <FileSearchOutlined />
          抓包源文件 <span className="mono">{sourcePath}</span>
          {record.ja4 ? <span className="anatomy__source-ja4 mono">JA4 {record.ja4}</span> : null}
        </a>
      ) : null}

      <div className="anatomy__grid">
        <div className="anatomy__pane anatomy__pane--ciphers">
          <div className="anatomy__pane-head">
            <span>cipher 列表</span>
            <span className="anatomy__count">{record.ciphers.length}</span>
          </div>
          <div
            className="anatomy__strip"
            role="img"
            aria-label={`${record.ciphers.length} 个 cipher，顺序与抓包一致`}
          >
            {record.ciphers.map((suite, index) => (
              <span
                key={`${suite}-${index}`}
                className={`anatomy__cell anatomy__cell--${cipherKind(suite)}`}
                title={suite}
              />
            ))}
          </div>
          <div className="anatomy__legend">
            {Object.entries(CIPHER_LEGEND).map(([kind, label]) => (
              <span className="anatomy__legend-item" key={kind}>
                <span className={`anatomy__cell anatomy__cell--${kind}`} />
                {label}
              </span>
            ))}
          </div>
          <div className="anatomy__mono-block mono">
            {record.ciphers.map((suite, index) => (
              <span key={`${suite}-line`} className="anatomy__mono-line">
                <span className="anatomy__mono-index">{index + 1}</span>
                {suite}
              </span>
            ))}
          </div>
        </div>

        <div className="anatomy__pane">
          <div className="anatomy__pane-head">
            <span>扩展顺序</span>
            <span className="anatomy__count">{record.extensionOrder.length}</span>
          </div>
          <ol className="anatomy__exts">
            {record.extensionOrder.map((id, index) => {
              const info = extensionLabel(id);
              return (
                <li className="anatomy__ext" key={`${id}-${index}`}>
                  <span className="anatomy__ext-pos">{index + 1}</span>
                  <span className="anatomy__ext-id mono">{id}</span>
                  <span className="anatomy__ext-name">{info.name}</span>
                </li>
              );
            })}
          </ol>
          {record.permuteExtensions ? (
            <p className="anatomy__aside">
              Chromium 每次连接都会重排这份列表：集合固定，顺序不固定。抓包里这一组只是其中一次。
            </p>
          ) : null}
        </div>

        <div className="anatomy__pane">
          <div className="anatomy__pane-head">
            <span>组与密钥共享</span>
          </div>
          <div className="anatomy__tags">
            {record.curves.map((curve) => {
              const shared = record.keyShares.includes(curve);
              return (
                <span
                  className={`anatomy__tag${shared ? " anatomy__tag--shared" : ""}`}
                  key={curve}
                  title={shared ? "这份握手里已经带了它的公钥" : "只声明支持，这次没带公钥"}
                >
                  {curve}
                </span>
              );
            })}
          </div>
          <p className="anatomy__aside">
            高亮的是这次真正带了 key share 的组；其余只是声明支持。第一个高亮的组，
            就是服务端要拿来做密钥交换的那个。
          </p>

          <div className="anatomy__pane-head anatomy__pane-head--spaced">
            <span>签名算法</span>
            <span className="anatomy__count">{record.sigalgs.length}</span>
          </div>
          <div className="anatomy__tags">
            {record.sigalgs.map((alg) => (
              <span className="anatomy__tag anatomy__tag--mono" key={alg}>
                {alg}
              </span>
            ))}
          </div>
        </div>

        <div className="anatomy__pane">
          <div className="anatomy__pane-head">
            <span>握手里的开关</span>
            {record.deviations.length > 0 ? (
              <span className="anatomy__count">{record.fidelity}</span>
            ) : null}
          </div>
          <ul className="anatomy__facts">
            <li>
              <span>版本</span>
              <span className="mono">
                TLS {record.minVersion} – {record.maxVersion}
              </span>
            </li>
            <li>
              <span>ALPN</span>
              <span className="mono">{record.alpn.join(", ") || "不声明"}</span>
            </li>
            {facts.map((entry) => (
              <li key={entry.label}>
                <span>{entry.label}</span>
                {"on" in entry && entry.on !== null ? (
                  <span className={`anatomy__flag${entry.on ? " anatomy__flag--on" : ""}`}>
                    {entry.text}
                  </span>
                ) : (
                  <span className="mono">{entry.text}</span>
                )}
              </li>
            ))}
          </ul>

          {record.deviations.length > 0 ? (
            <div className="anatomy__deviation">
              <span className="anatomy__deviation-label">
                这条记录里，BoringSSL 发不出来的项：
              </span>
              <ul>
                {record.deviations.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
              <span className="anatomy__deviation-foot">
                上面的列表是抓包里的原样；线路上的字节会少掉这几项，所以保真度是
                {record.fidelity === "close" ? " close" : " partial"}。
              </span>
            </div>
          ) : null}

          <div className="anatomy__pane-head anatomy__pane-head--spaced">
            <span>第一个 HTTP/2 帧</span>
          </div>
          {record.http2 ? (
            <>
              <div className="anatomy__tags">
                {record.http2.settings.map((setting) => (
                  <span className="anatomy__tag anatomy__tag--mono" key={setting.id}>
                    {setting.id}:{setting.value}
                  </span>
                ))}
              </div>
              <p className="anatomy__aside">
                伪头顺序 <span className="mono">{record.http2.pseudoOrder}</span>
                {record.http2.windowUpdate !== null ? (
                  <>
                    ，连接窗口更新 <span className="mono">{record.http2.windowUpdate}</span>
                  </>
                ) : null}
                。
              </p>
            </>
          ) : (
            <p className="anatomy__aside">这条记录没有抓到 HTTP/2 的首帧，只用 HTTP/1.1 或走 QUIC。</p>
          )}
        </div>
      </div>
    </section>
  );
}

import { useMemo, useState } from "react";
import { handshakes } from "../data/handshakes";

// One JA4, taken apart. Its three underscores divide the string into what the
// server can fingerprint: a coarse type letter, the cipher and extension counts,
// and two hash prefixes — one over the ciphers and extensions, one over the
// signature algorithms and SNI.

const LETTERS: Record<string, string> = {
  t: "TLS over TCP",
  q: "QUIC（HTTP/3）",
  d: "DTLS",
};

const EXAMPLES = ["chrome158", "firefox160", "ios_safari26", "android_okhttp13", "go1.26"];

export function Ja4Breakdown() {
  const [name, setName] = useState("chrome158");
  const record = useMemo(
    () => handshakes.find((handshake) => handshake.name === name && handshake.ja4),
    [name],
  );

  if (!record) return null;

  const [a, b, c] = record.ja4.split("_");
  const version = a.slice(1, 3);
  const sni = a.slice(3, 4);
  const ciphers = Number(a.slice(4, 6));
  const extensions = Number(a.slice(6, 8));
  const alpn = a.slice(8);

  const parts = [
    {
      value: a,
      label: "协议与计数",
      note: `${LETTERS[a[0]] ?? a[0]}，TLS ${version === "13" ? "1.3" : version === "12" ? "1.2" : "1.0"}。这一段是可读的计数，后面两段才是哈希。`,
      detail: [
        { k: "SNI", v: sni === "d" ? "带了主机名" : "没带" },
        { k: "cipher 数", v: String(ciphers) },
        { k: "扩展数", v: String(extensions) },
        { k: "ALPN", v: alpn || "无" },
      ],
    },
    {
      value: b,
      label: "cipher 与扩展的哈希",
      note: "把 cipher 列表与扩展列表规范化后取 SHA-256 的前 12 字节。",
      detail: [
        { k: "来源", v: Boolean(record.ja4r) ? "见下方原始码点" : "抓包里没有 ja4_r" },
        { k: "参与字段", v: "cipher 列表 + 扩展列表" },
      ],
    },
    {
      value: c,
      label: "签名算法与 SNI 的哈希",
      note: "只覆盖签名算法列表与 SNI 值，所以同样的 cipher 换一组签名算法也会变。",
      detail: [{ k: "参与字段", v: "签名算法列表 + SNI" }],
    },
  ];

  return (
    <section className="section ja4">
      <div className="section__head">
        <span className="section__kicker">JA4 是怎么算出来的</span>
        <h2 className="section__title">一串哈希里的三段，各看什么</h2>
        <p className="section__lede">
          JA4 由三个下划线分成四块。第一块是协议、版本与两个计数；后两块是哈希前缀。
          选一条记录，看它的 JA4 每一段对应到握手里的哪一栏。
        </p>
      </div>

      <div className="ja4__switch">
        {EXAMPLES.map((example) => (
          <button
            key={example}
            type="button"
            className={`ja4__pick${example === name ? " is-on" : ""}`}
            onClick={() => setName(example)}
          >
            {example}
          </button>
        ))}
      </div>

      <div className="ja4__string mono" aria-label={`JA4 ${record.ja4}`}>
        {parts.map((part, index) => (
          <span key={part.label} className={`ja4__seg ja4__seg--${index}`}>
            {part.value}
            {index < parts.length - 1 ? <span className="ja4__sep">_</span> : null}
          </span>
        ))}
      </div>

      <div className="ja4__parts">
        {parts.map((part, index) => (
          <div className={`ja4__part ja4__part--${index}`} key={part.label}>
            <div className="ja4__part-head">
              <span className="ja4__part-label">{part.label}</span>
              <span className="ja4__part-value mono">{part.value}</span>
            </div>
            <p className="ja4__note">{part.note}</p>
            {part.detail.length > 0 ? (
              <ul className="ja4__detail">
                {part.detail.map((row) => (
                  <li key={row.k}>
                    <span>{row.k}</span>
                    <span className="mono">{row.v}</span>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        ))}
      </div>

      {record.ja4r ? (
        <div className="ja4__raw">
          <span className="ja4__raw-label">
            `ja4_r` 是同一串指纹的可读版本：cipher 与扩展用码点而不是计数。
          </span>
          <span className="mono ja4__raw-value">{record.ja4r.split("_").slice(1, 3).join("_")}</span>
        </div>
      ) : null}
    </section>
  );
}

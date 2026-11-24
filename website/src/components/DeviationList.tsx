import { useMemo, useState } from "react";
import { records } from "../data/library";

// The differences that make a record close or partial, grouped by what the
// capture had and BoringSSL could not match. The matchers are read off the
// deviation text the capture tooling writes, so a new kind of gap lands in a
// sensible bucket instead of disappearing.

interface Kind {
  key: string;
  label: string;
  match: RegExp;
  why: string;
}

const KINDS: Kind[] = [
  {
    key: "order",
    label: "套件顺序",
    match: /always sends the TLS 1\.3 cipher suites/i,
    why: "BoringSSL 固定把 TLS 1.3 套件排在前面，抓包里它们在 TLS 1.2 之后。JA4 的 b 段会因此不同。",
  },
  {
    key: "extra",
    label: "多发的扩展",
    match: /always sends extended_master_secret/i,
    why: "BoringSSL 默认就发 EMS，抓包的客户端没发；这一项是「多了一个」而不是「少了一个」。",
  },
  {
    key: "grease",
    label: "GREASE 范围",
    match: /greases only/i,
    why: "抓包里的客户端只对部分列表做 GREASE，BoringSSL 的开关会同时搅动套件、组、版本、key share 与扩展五处。",
  },
  {
    key: "alpn",
    label: "只谈 HTTP/1.1",
    match: /ran over HTTP\/1\.1/i,
    why: "这次抓包只协商了 http/1.1，客户端完整的 h2 列表没有出现，记录也因此不能代表它的 HTTP/2 指纹。",
  },
  {
    key: "ciphers",
    label: "cipher 套件",
    match: /cannot send .*cipher suites?/i,
    why: "通常是 OpenSSL 系的 DHE、CCM、RC4 套件或空重协商标记，BoringSSL 不认识这些名字。",
  },
  {
    key: "groups",
    label: "命名组",
    match: /cannot send .*groups?/i,
    why: "X448、ffdhe4096 以上的大 DH 组，BoringSSL 的组表里没有。",
  },
  {
    key: "sigalgs",
    label: "签名算法",
    match: /cannot send .*signature algorithms?/i,
    why: "ML-DSA、ed448、brainpool 与 sha224 系列；BoringSSL 只发它编译进去的那几种。",
  },
];

export function DeviationList() {
  const [kind, setKind] = useState<string | null>(null);

  const grouped = useMemo(
    () =>
      KINDS.map((entry) => ({
        ...entry,
        records: records
          .map((record) => ({
            name: record.name,
            line: record.deviations.find((line) => entry.match.test(line)),
          }))
          .filter((record): record is { name: string; line: string } => Boolean(record.line)),
      })),
    [],
  );

  const shown = kind ? grouped.filter((entry) => entry.key === kind) : grouped;
  const total = records.filter((record) => record.deviations.length > 0).length;

  return (
    <>
      <div className="dev__kinds">
        <button
          type="button"
          className={`dev__kind${kind === null ? " is-on" : ""}`}
          onClick={() => setKind(null)}
        >
          全部 {total}
        </button>
        {grouped
          .filter((entry) => entry.records.length > 0)
          .map((entry) => (
            <button
              key={entry.key}
              type="button"
              className={`dev__kind${kind === entry.key ? " is-on" : ""}`}
              onClick={() => setKind(entry.key)}
            >
              {entry.label} {entry.records.length}
            </button>
          ))}
      </div>
      <p className="dev__note">
        一条记录常常同时缺几类，所以各格之和大于 {total}。下面每一条只引用了与该种类相关的那一行 deviation。
      </p>

      <div className="dev__list">
        {shown
          .filter((entry) => entry.records.length > 0)
          .map((entry) => (
            <div className="dev__group" key={entry.key}>
              <div className="dev__group-head">
                <span className="dev__group-label">{entry.label}</span>
                <span className="dev__group-count">{entry.records.length} 条记录</span>
              </div>
              <p className="dev__why">{entry.why}</p>
              <ul className="dev__names">
                {entry.records.slice(0, 8).map((record) => (
                  <li key={record.name} className="mono">
                    {record.name}
                    <span className="dev__line">{record.line}</span>
                  </li>
                ))}
              </ul>
              {entry.records.length > 8 ? (
                <span className="dev__more">
                  另有 {entry.records.length - 8} 条，指纹库可按家族筛。
                </span>
              ) : null}
            </div>
          ))}
      </div>
    </>
  );
}

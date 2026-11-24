import { useMemo } from "react";
import { handshakes } from "../data/handshakes";
import { cipherKind } from "../data/handshakes";

// The library's 32 cipher suites, ordered by how many records offer them. The
// long tail matters: a suite only 30 records send is exactly the field a server
// would use to tell those 30 apart.

const KIND_LABEL: Record<string, string> = {
  tls13: "TLS 1.3",
  chacha: "ChaCha20",
  gcm: "AES-GCM",
  cbc: "CBC",
  dhe: "DHE",
  rsa: "RSA 密钥交换",
};

export function SuiteFrequency() {
  const rows = useMemo(() => {
    const counts = new Map<string, number>();
    for (const handshake of handshakes) {
      for (const suite of handshake.ciphers) {
        counts.set(suite, (counts.get(suite) ?? 0) + 1);
      }
    }
    return Array.from(counts.entries())
      .map(([suite, count]) => ({ suite, count, kind: cipherKind(suite) }))
      .sort((a, b) => b.count - a.count);
  }, []);

  const total = handshakes.length;
  const rare = rows.filter((row) => row.count <= total / 5).length;
  const common = rows.filter((row) => row.count > total / 2).length;

  return (
    <section className="section">
      <div className="section__head">
        <span className="section__kicker">套件从哪来到哪去</span>
        <h2 className="section__title">
          {rows.length} 个套件，{common} 个几乎人人都有
        </h2>
        <p className="section__lede">
          每一行是「多少条记录发了这个套件」，按出现次数排列。靠前的套件大家都发，
          区分不了谁；越往下越少见，有 {rare} 个套件的出现次数不到 {Math.round(total / 5)} 条，
          它们才是把某一个家族从其他家族里分出来的东西。
        </p>
      </div>

      <div className="suite__list">
        {rows.map((row) => (
          <div className="suite__row" key={row.suite} title={`${row.suite} · ${KIND_LABEL[row.kind]}`}>
            <span className={`suite__kind suite__kind--${row.kind}`} />
            <span className="suite__name mono">{row.suite.replace(/^TLS_/, "")}</span>
            <span className="suite__bar">
              <span
                className={`suite__fill suite__fill--${row.kind}`}
                style={{ width: `${(row.count / total) * 100}%` }}
              />
            </span>
            <span className="suite__count mono">{row.count}</span>
          </div>
        ))}
      </div>

      <div className="suite__legend">
        {Object.entries(KIND_LABEL).map(([kind, label]) => (
          <span className="suite__legend-item" key={kind}>
            <span className={`suite__kind suite__kind--${kind}`} />
            {label}
          </span>
        ))}
      </div>
    </section>
  );
}

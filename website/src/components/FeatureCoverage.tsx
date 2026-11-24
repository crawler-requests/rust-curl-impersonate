import { handshakes } from "../data/handshakes";
import { familySummary } from "../data/library";

// What the records of one page actually enable, counted rather than claimed.
// A feature the family never sends (GREASE in Firefox, ALPS in Safari) is worth
// knowing before someone picks a record expecting it.

const FEATURES = [
  { key: "grease", label: "GREASE", why: "在 cipher / 组 / 版本列表里插入随机值，JA3 里会被忽略。" },
  { key: "echGrease", label: "ECH GREASE", why: "找不到 ECHConfig 时的占位，改变报文长度。" },
  { key: "alps", label: "ALPS", why: "把 HTTP/2 设置挪进握手里预协商。" },
  { key: "permuteExtensions", label: "扩展重排", why: "每次连接重新排扩展列表，集合固定、顺序不固定。" },
  { key: "certCompression", label: "证书压缩", why: "要求服务端按 brotli / zstd / zlib 压缩证书。" },
  { key: "http2", label: "HTTP/2 首帧", why: "抓到了 SETTINGS 与伪头顺序，才谈得上 Akamai 指纹。" },
] as const;

/** Which member families a page owns, from the family summary keys. */
export function FeatureCoverage({ members }: { members: string[] }) {
  const records = handshakes.filter((handshake) => members.includes(handshake.family));
  if (records.length === 0) return null;

  return (
    <section className="section">
      <div className="section__head">
        <span className="section__kicker">这一族的握手开了哪些选项</span>
        <h2 className="section__title">特性不是每族都有</h2>
        <p className="section__lede">
          下表按记录计数：{records.length} 条记录里，有多少条真的带上了这一项。
          选中一个选项不等于服务端能看到它——有些族从来不发 GREASE，有些族的抓包没有 h2 首帧。
        </p>
      </div>
      <div className="coverage__grid">
        {FEATURES.map((feature) => {
          const on = records.filter((record) => {
            const value = record[feature.key];
            if (typeof value === "boolean") return value;
            if (Array.isArray(value)) return value.length > 0;
            return value !== null;
          }).length;
          const ratio = on / records.length;
          return (
            <div className="coverage__item" key={feature.key}>
              <div className="coverage__head">
                <span className="coverage__label">{feature.label}</span>
                <span className="coverage__count mono">
                  {on} / {records.length}
                </span>
              </div>
              <span className="coverage__bar">
                <span
                  className={`coverage__fill${ratio === 0 ? " coverage__fill--zero" : ""}`}
                  style={{ width: `${Math.max(ratio * 100, ratio === 0 ? 2 : 6)}%` }}
                />
              </span>
              <span className="coverage__why">{feature.why}</span>
            </div>
          );
        })}
      </div>
      <p className="coverage__note">
        说明：这些计数来自 <span className="mono">src/fingerprint/builtin.json</span> 的 tls 字段，
        共覆盖 {familySummary.length} 个家族的全部记录。
      </p>
    </section>
  );
}

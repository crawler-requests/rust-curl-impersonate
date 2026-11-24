import { useState } from "react";
import { records } from "../data/library";
import { FidelityTag } from "./FidelityTag";
import { familySummary } from "../data/library";

// Where the exact / close / partial split falls, family by family. The numbers
// are counted from the library at render time, so they follow the records.

const LEVELS = ["exact", "close", "partial"] as const;
type Level = (typeof LEVELS)[number];

const LEVEL_LABEL: Record<Level, string> = {
  exact: "逐字节一致",
  close: "少数项发不出",
  partial: "缺项较多",
};

export function FidelityBreakdown() {
  const [level, setLevel] = useState<Level | null>(null);

  const rows = familySummary.map((family) => {
    const list = records.filter((record) => record.family === family.key);
    const counts = {
      exact: list.filter((record) => record.fidelity === "exact").length,
      close: list.filter((record) => record.fidelity === "close").length,
      partial: list.filter((record) => record.fidelity === "partial").length,
    };
    return { family, total: list.length, counts };
  });

  const shown = level ? rows.filter((row) => row.counts[level] > 0) : rows;
  // A selected level redraws each bar as that level alone, on the same scale,
  // so the comparison is between families rather than inside one bar.
  const widthOf = (row: (typeof rows)[number]) =>
    level ? row.counts[level] : row.total;
  const max = Math.max(...shown.map(widthOf), 1);

  return (
    <section className="section">
      <div className="section__head">
        <span className="section__kicker">按家族看</span>
        <h2 className="section__title">哪一族真的逐字节一致</h2>
        <p className="section__lede">
          条形的总长是这个家族的记录数，颜色是保真度。exact 表示抓包里的字段 BoringSSL 全部发得出；
          close 是少数项发不出、差额写在 deviations 里；partial 是缺得较多、形状已明显不同。
          点一下图例只看某一档，能看出 exact 集中在找得到同一实现的家族，partial 集中在 OpenSSL 系的运行时。
        </p>
      </div>

      <div className="fab__legend">
        <button
          type="button"
          className={`fab__legend-item${level === null ? " is-on" : ""}`}
          onClick={() => setLevel(null)}
        >
          全部 {records.length}
        </button>
        {LEVELS.map((entry) => (
          <button
            key={entry}
            type="button"
            className={`fab__legend-item fab__legend-item--${entry}${level === entry ? " is-on" : ""}`}
            onClick={() => setLevel(entry)}
          >
            <FidelityTag value={entry} />
            {LEVEL_LABEL[entry]} {records.filter((record) => record.fidelity === entry).length}
          </button>
        ))}
      </div>

      <div className="fab__rows">
        {shown.map((row) => (
          <div className="fab__row" key={row.family.key}>
            <span className="fab__name">{row.family.label}</span>
            <span className="fab__bar" style={{ width: `${(widthOf(row) / max) * 100}%` }}>
              {(level ? [level] : LEVELS).map((entry) =>
                row.counts[entry] > 0 ? (
                  <span
                    key={entry}
                    className={`fab__seg fab__seg--${entry}`}
                    style={{ flexGrow: row.counts[entry] }}
                    title={`${LEVEL_LABEL[entry]} ${row.counts[entry]} 条`}
                  />
                ) : null,
              )}
            </span>
            <span className="fab__count">{widthOf(row)}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

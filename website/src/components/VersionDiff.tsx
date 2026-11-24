import { useEffect, useMemo, useState } from "react";
import { differencesBetween, handshakeFor } from "../data/handshakes";
import type { Handshake } from "../data/handshakes";
import { FidelityTag } from "./FidelityTag";

// Two records of one family, compared field by field. The differences are
// computed from the captures, so the panel answers "does a version bump
// matter?" with the record's own numbers instead of a promise.

// The caller passes the page's own record names, so the comparison follows
// what the page shows: Chrome's page compares its versions, the runtimes page
// compares Go, Python and Node against each other.
export function VersionDiff({ names }: { names: string[] }) {
  const list = useMemo(() => {
    const records = names
      .map((name) => handshakeFor(name))
      .filter((handshake): handshake is Handshake => Boolean(handshake))
      .sort((a, b) => b.extensionOrder.length - a.extensionOrder.length);
    return records;
  }, [names]);

  if (list.length < 2) return null;

  return <DiffBody list={list} />;
}

function DiffBody({ list }: { list: Handshake[] }) {
  // Default to two records of the same family: "同一族里两个版本" is the
  // question, and on the runtimes page the first two records are normally
  // different languages. `left` is the newest record whose family has a
  // second entry, and `right` the next one in that family.
  const defaultPair = useMemo(() => {
    for (let index = 0; index < list.length; index += 1) {
      const twin = list.findIndex(
        (other, at) => at !== index && other.family === list[index].family,
      );
      if (twin >= 0) return [index, twin] as const;
    }
    return [0, Math.min(1, list.length - 1)] as const;
  }, [list]);

  const [left, setLeft] = useStateSafe(defaultPair[0], list);
  const [right, setRight] = useStateSafe(defaultPair[1], list);

  const a = list[left];
  const b = list[right];
  const diffs = differencesBetween(a, b);

  return (
    <section className="section diff">
      <div className="section__head">
        <span className="section__kicker">同一族里两个版本</span>
        <h2 className="section__title">换个版本，到底差在哪</h2>
        <p className="section__lede">
          左边右边各选一条记录。下表的每一行都是抓包之间真实存在的差别，
          不是版本号变了就算有差别；只留下真正不同的字段。
        </p>
      </div>

      <div className="diff__picks">
        <span className="diff__count">{list.length} 条可对比</span>
        <select
          className="diff__select"
          value={left}
          onChange={(event) => setLeft(Number(event.target.value))}
          aria-label="左边的记录"
        >
          {list.map((item, index) => (
            <option key={item.name} value={index}>
              {item.name} · {item.version || "—"}
            </option>
          ))}
        </select>
        <span className="diff__vs">对比</span>
        <select
          className="diff__select"
          value={right}
          onChange={(event) => setRight(Number(event.target.value))}
          aria-label="右边的记录"
        >
          {list.map((item, index) => (
            <option key={item.name} value={index}>
              {item.name} · {item.version || "—"}
            </option>
          ))}
        </select>
      </div>

      <div className="diff__heads">
        <div className="diff__head">
          <span className="mono">{a.name}</span>
          <span className="diff__head-meta">{a.version || "—"}</span>
          <FidelityTag value={a.fidelity} />
        </div>
        <div className="diff__head">
          <span className="mono">{b.name}</span>
          <span className="diff__head-meta">{b.version || "—"}</span>
          <FidelityTag value={b.fidelity} />
        </div>
      </div>

      <table className="diff__table">
        <thead>
          <tr>
            <th>字段</th>
            <th>{a.name}</th>
            <th>{b.name}</th>
          </tr>
        </thead>
        <tbody>
          {diffs.map((diff) => (
            <tr key={diff.label}>
              <td>{diff.label}</td>
              <td className="mono">{diff.from}</td>
              <td className="mono">{diff.to}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {a.ja4 === b.ja4 ? (
        <p className="diff__note">
          这两条记录的 JA4 相同：服务端看到的指纹一样，换与不换在大多数检测里没有区别。
        </p>
      ) : (
        <p className="diff__note">
          两条记录的 JA4 不同，服务端能把它们分开。
        </p>
      )}
    </section>
  );
}

// The selects index into the list the page passes. Navigating from one family
// page to another swaps that list under the same component, so a selection
// left out of range has to snap back rather than render `undefined`.
function useStateSafe(initial: number, list: Handshake[]) {
  const [value, setValue] = useState(initial);
  const max = Math.max(list.length - 1, 0);
  useEffect(() => {
    if (value > max) setValue(max);
  }, [max, value]);
  return [Math.min(value, max), setValue] as const;
}

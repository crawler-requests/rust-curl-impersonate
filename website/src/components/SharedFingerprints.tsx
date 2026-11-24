import { useMemo } from "react";
import { handshakes } from "../data/handshakes";
import type { Handshake } from "../data/handshakes";

// Which versions of a family are actually indistinguishable to a server.
// Grouped by JA4, which is what a fingerprinting server reads first: records in
// one group send the same hello, so picking between them changes nothing on the
// wire.

function isNative(name: string): boolean {
  // tlsclient/utls records are ClientHello definitions played back by a
  // library, not a process from the vendor; grouping them with a real browser
  // build would mix two different kinds of evidence.
  return !name.startsWith("tlsclient_") && !name.startsWith("utls_");
}

export function SharedFingerprints({ names, familyLabel }: { names: string[]; familyLabel: string }) {
  const groups = useMemo(() => {
    const records = new Set(names);
    const byJa4 = new Map<string, Handshake[]>();
    for (const handshake of handshakes) {
      if (!records.has(handshake.name) || !isNative(handshake.name) || !handshake.ja4) continue;
      const list = byJa4.get(handshake.ja4) ?? [];
      list.push(handshake);
      byJa4.set(handshake.ja4, list);
    }
    return Array.from(byJa4.entries())
      .map(([ja4, list]) => ({
        ja4,
        names: list.map((item) => item.name).sort(),
        versions: list
          .map((item) => item.version || item.name)
          .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
          .slice(0, 6)
          .join("、"),
      }))
      .filter((group) => group.names.length > 1)
      .sort((a, b) => b.names.length - a.names.length);
  }, [names]);

  if (groups.length === 0) {
    return (
      <section className="section">
        <span className="section__kicker">同一族的版本之间</span>
        <h2 className="section__title">每一条记录的指纹都不同</h2>
        <p className="section__lede">
          {familyLabel}的这一批原生抓包里没有两个版本发出相同的 JA4，所以选错版本会被直接看出来。
        </p>
      </section>
    );
  }

  const merged = groups.reduce((total, group) => total + group.names.length, 0);
  // "Family" here means a member family of the page (chrome, edge, brave …),
  // not the page's own grouping, so the runtimes page reads "这些家族".
  const families = new Set(names.map((name) => name.replace(/[^a-z].*/, "")));

  return (
    <section className="section">
      <div className="section__head">
        <span className="section__kicker">同一族的版本之间</span>
        <h2 className="section__title">这些版本在服务端是同一个客户端</h2>
        <p className="section__lede">
          按 JA4 分组：同一组里的记录发出的握手一致，选哪个在线上没有区别。
          {families.size > 1 ? "这些家族" : familyLabel + "这一族"}的原生抓包里，
          {merged} 条记录落在 {groups.length} 个这样的组里。
          只统计原生抓包，uTLS 与 tls-client 的 ClientHello 定义不参与分组。
        </p>
      </div>
      <div className="shared__list">
        {groups.map((group) => (
          <div className="shared__group" key={group.ja4}>
            <span className="shared__ja4 mono">{group.ja4}</span>
            <span className="shared__names mono">{group.names.join("、")}</span>
            <span className="shared__versions">{group.versions}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

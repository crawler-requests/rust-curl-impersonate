import { useMemo, useState } from "react";
import { Input, Table, Typography } from "antd";
import { Link } from "react-router-dom";
import type { FamilyPage as FamilySpec } from "../data/families";
import { aliasesOf, recordsOf } from "../data/families";
import { traitsFor } from "../data/traits";
import type { FingerprintRecord } from "../data/library";
import { handshakeFor } from "../data/handshakes";
import { FidelityTag } from "../components/FidelityTag";
import { HandshakeAnatomy } from "../components/HandshakeAnatomy";
import { VersionDiff } from "../components/VersionDiff";
import { SharedFingerprints } from "../components/SharedFingerprints";
import { FeatureCoverage } from "../components/FeatureCoverage";
import { familyIcon } from "../components/icons";
import { CodeBlock, Comment, Str } from "../components/CodeBlock";

// One page per client family: what makes that family's hello its own, which
// records belong to it, and how far apart the versions inside it are.

/** The chip label for a record's family, as the library names it in Chinese. */
function familyLabel(family: string): string {
  const labels: Record<string, string> = {
    chrome: "Chrome",
    firefox: "Firefox",
    safari: "Safari",
    ios: "iOS",
    android: "Android",
    okhttp: "OkHttp",
    go: "Go",
    python: "Python",
    node: "Node",
    php: "PHP",
    java: "Java",
    dotnet: ".NET",
    ruby: "Ruby",
    curl: "curl",
    wget: "wget",
    openssl: "OpenSSL",
    rust: "Rust",
    perl: "Perl",
    erlang: "Erlang",
    bun: "Bun",
    deno: "Deno",
    dart: "Dart",
    cloudflare: "Cloudflare",
    edge: "Edge",
    brave: "Brave",
    opera: "Opera",
    "360": "360",
    qq: "QQ",
  };
  return labels[family] ?? family;
}

/**
 * Ranks a record by version in a way that survives the library's mixed
 * naming. The record name is the reliable source — `python3.12_requests`
 * carries 3.12 while its `version` field is the requests release, 2.32.5 —
 * so the first number in the name (with an optional minor) wins, and the
 * `version` field is only a fallback.
 */
function versionRank(record: { name: string; version: string }): number {
  const fromName = record.name.match(/(\d+)(?:\.(\d+))?/);
  const fromVersion = record.version.match(/(\d+)(?:\.(\d+))?/);
  const pick = fromName ?? fromVersion;
  if (!pick) return -1;
  return Number(pick[1]) * 1000 + Number(pick[2] ?? 0);
}

export function FamilyPage({ spec }: { spec: FamilySpec }) {
  const all = useMemo(() => recordsOf(spec), [spec]);
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return all;
    return all.filter(
      (record) =>
        record.name.toLowerCase().includes(needle) ||
        record.client.toLowerCase().includes(needle) ||
        record.ja4.toLowerCase().includes(needle),
    );
  }, [all, query]);

  const traits = useMemo(() => traitsFor(spec.members), [spec]);

  // Records the anatomy panel can switch between: the ones that captured a
  // real TLS layer, newest versions first, capped so the switch stays readable.
  const anatomyPicks = useMemo(() => {
    const withHandshake = all.filter((record) => handshakeFor(record.name));
    const latest = (list: typeof withHandshake) =>
      list
        .slice()
        .sort((a, b) => versionRank(b) - versionRank(a));
    const picks = [
      ...latest(withHandshake.filter((record) => record.fidelity === "exact")),
      ...latest(withHandshake.filter((record) => record.fidelity !== "exact")),
    ];
    // One toggle per family: Runtimes holds ten Python versions that all send
    // OpenSSL's ClientHello, and ten switches for them would hide the fact
    // that Go, Node and Python differ at all. Chrome, Edge and Brave get one
    // toggle each because they are the same BoringSSL build with different
    // extension sets.
    const byFamily = new Map<string, { record: FingerprintRecord; count: number }>();
    for (const record of picks) {
      const entry = byFamily.get(record.family);
      if (entry) entry.count += 1;
      else byFamily.set(record.family, { record, count: 1 });
    }
    // The family with the most records leads, which puts Chrome first on the
    // Chrome page and Python first on the runtimes page.
    return Array.from(byFamily.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 8)
      .map(({ record }) => ({
        key: record.name,
        label:
          familyLabel(record.family) +
          (record.version ? ` ${record.version.split(".")[0]}` : ""),
      }));
  }, [all]);
  const aliasList = aliasesOf(spec);

  // A handful of records spread across the family for the version comparison:
  // the oldest and newest of each family on the page, capped so the two
  // selects stay usable.
  const diffNames = useMemo(() => {
    const byFamily = new Map<string, FingerprintRecord[]>();
    for (const record of all) {
      if (!handshakeFor(record.name)) continue;
      const list = byFamily.get(record.family) ?? [];
      list.push(record);
      byFamily.set(record.family, list);
    }
    // Every record of a family that owns this page (Chrome, Firefox, …) is
    // listed, newest first, so the two selects pair two nearby versions; the
    // shared families get their oldest and newest only, which keeps the
    // runtimes page from listing two hundred Python releases.
    const names: string[] = [];
    for (const [family, list] of byFamily) {
      const ranked = list.slice().sort((x, y) => versionRank(y) - versionRank(x));
      const owned = spec.members.includes(family);
      const wanted = owned ? ranked : [ranked[0], ranked[ranked.length - 1]];
      for (const record of wanted) {
        if (record && !names.includes(record.name)) names.push(record.name);
      }
    }
    return names.slice(0, 40);
  }, [all]);
  const exact = all.filter((record) => record.fidelity === "exact").length;

  const columns = [
    {
      title: "记录",
      dataIndex: "name",
      key: "name",
      render: (value: string) => (
        <span className="mono" style={{ fontSize: 12.5 }}>
          {value}
        </span>
      ),
      sorter: (a: FingerprintRecord, b: FingerprintRecord) =>
        a.name.localeCompare(b.name),
    },
    {
      title: "客户端",
      dataIndex: "client",
      key: "client",
      render: (value: string, record: FingerprintRecord) => (
        <>
          <div>{value}</div>
          {record.version ? (
            <div className="note" style={{ fontSize: 12 }}>
              {record.version}
            </div>
          ) : null}
        </>
      ),
    },
    {
      title: "JA4",
      dataIndex: "ja4",
      key: "ja4",
      render: (value: string) =>
        value ? (
          <span className="mono" style={{ fontSize: 11.5, color: "var(--ink-muted)" }}>
            {value}
          </span>
        ) : (
          "—"
        ),
    },
    {
      title: "保真度",
      dataIndex: "fidelity",
      key: "fidelity",
      width: 92,
      render: (value: FingerprintRecord["fidelity"]) => <FidelityTag value={value} />,
    },
  ];

  return (
    <>
      <section className="hero hero--compact">
        <div className="family-hero">
          <span className="family-hero__icon">{familyIcon(spec.members[0])}</span>
          <div className="hero__eyebrow">{spec.nav}</div>
        </div>
        <h1 className="hero__title">{spec.title}</h1>
        <p className="hero__lede">{spec.lede}</p>
        <div className="chip-row">
          <span className="chip">{all.length} 条记录</span>
          <span className="chip">{exact} 条 exact</span>
          {spec.members.length > 1 ? (
            <span className="chip">{spec.members.length} 个家族</span>
          ) : null}
        </div>
      </section>

      <section className="section">
        <span className="section__kicker">这一族的握手有什么不同</span>
        <h2 className="section__title">三个能把它认出来的特征</h2>
        <div className="issue-grid">
          {traits.map((trait) => (
            <div className="issue-card" key={trait.title}>
              <div className="issue-card__title">{trait.title}</div>
              <div className="issue-card__body">{trait.body}</div>
            </div>
          ))}
        </div>
      </section>

      {anatomyPicks.length > 0 ? (
        <HandshakeAnatomy
          picks={anatomyPicks}
          kicker="这一族在线上发的是什么"
          title="拆开一条，看它到底发了什么"
          lede="下面选的是这一族里最新的几条记录。cipher 列表、扩展顺序、命名组与 key share 都按抓包原样列出；换一条记录，整块内容跟着换。"
        />
      ) : null}

      <section className="section">
        <div className="section__head">
          <span className="section__kicker">全部记录</span>
          <h2 className="section__title">{all.length} 条来自真实抓包</h2>
          <Typography.Paragraph className="section__lede">
            同一族内的版本差异往往只有一两个扩展，所以记录按名称、客户端或 JA4 都能搜。
            {aliasList.length > 0
              ? `另有 ${aliasList.length} 个别名指向这里的基础记录。`
              : ""}
          </Typography.Paragraph>
          <Input
            allowClear
            placeholder="搜索名称、客户端或 JA4"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            style={{ maxWidth: 340 }}
          />
        </div>
        <Table
          rowKey="name"
          size="small"
          columns={columns}
          dataSource={filtered}
          pagination={{ pageSize: 20, showSizeChanger: false }}
          // Without this the table keeps its own width on a phone and
          // stretches the whole page sideways.
          scroll={{ x: 560 }}
        />
      </section>

      <VersionDiff names={diffNames} />

      <SharedFingerprints names={diffNames} familyLabel={spec.nav} />

      <FeatureCoverage members={spec.members} />

      <section className="section">
        <span className="section__kicker">怎么选</span>
        <h2 className="section__title">按版本挑，而不是挑一个近似的</h2>
        <CodeBlock>
          <Comment>{"// 记录名就是 Profile::find 的参数\n"}</Comment>
          {all.slice(0, 2).map((record) => (
            <span key={record.name}>
              {"let client = Client::new(Profile::find("}
              <Str>{`"${record.name}"`}</Str>
              {")?)?;\n"}
            </span>
          ))}
          {aliasList.slice(0, 1).map((alias) => (
            <span key={alias.name}>
              <Comment>{"// 别名\n"}</Comment>
              {"let client = Client::new(Profile::find("}
              <Str>{`"${alias.name}"`}</Str>
              {")?)?;\n"}
            </span>
          ))}
        </CodeBlock>
        {traits.length > 0 ? (
          <p className="note" style={{ marginTop: 16 }}>
            <Link to="/library">指纹库</Link> 页可以按家族筛选，并只看 exact 的记录。
          </p>
        ) : null}
      </section>
    </>
  );
}

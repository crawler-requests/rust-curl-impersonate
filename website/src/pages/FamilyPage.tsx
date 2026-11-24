import { useMemo, useState } from "react";
import { Input, Table, Typography } from "antd";
import { Link } from "react-router-dom";
import type { FamilyPage as FamilySpec } from "../data/families";
import { aliasesOf, recordsOf } from "../data/families";
import { traitsFor } from "../data/traits";
import type { FingerprintRecord } from "../data/library";
import { FidelityTag } from "../components/FidelityTag";
import { familyIcon } from "../components/icons";
import { CodeBlock, Comment, Str } from "../components/CodeBlock";

// One page per client family: what makes that family's hello its own, which
// records belong to it, and how far apart the versions inside it are.

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
  const aliasList = aliasesOf(spec);
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

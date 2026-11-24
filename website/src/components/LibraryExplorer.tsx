import { useMemo, useState } from "react";
import { Button, Input, Segmented, Select, Table, Tag, Typography } from "antd";
import { Link } from "react-router-dom";
import { aliases, records } from "../data/library";
import type { FingerprintRecord } from "../data/library";
import { familyOf } from "../data/families";
import { FidelityTag } from "./FidelityTag";

// The whole built-in library, searchable. The list is generated from the
// crate, so what the site shows is what the library ships.

const families = Array.from(new Set(records.map((r) => r.family).filter(Boolean)).values())
  .sort()
  .map((family) => ({ label: family, value: family }));

// Only a family with a page of its own gets a link here. The runtimes page
// owns seventeen families, and repeating "运行时" on every row would say
// nothing; the family select already covers that case.
function specificPage(family: string) {
  const page = familyOf(family);
  return page && page.members.length > 0 && page.key !== "runtimes" && page.members.length <= 6
    ? page
    : undefined;
}

const platforms = Array.from(
  new Set(records.map((r) => r.platform).filter(Boolean)).values(),
)
  .sort()
  .map((platform) => ({ label: platform, value: platform }));

const columns = [
  {
    title: "名称",
    dataIndex: "name",
    key: "name",
    render: (value: string, record: FingerprintRecord) => (
      <span className="mono" style={{ fontSize: 12.5 }}>
        {value}
        {specificPage(record.family) ? (
          <Link
            to={specificPage(record.family)!.path}
            className="library__family-link"
            title={`去看 ${specificPage(record.family)!.title}`}
          >
            {specificPage(record.family)!.nav}
          </Link>
        ) : null}
      </span>
    ),
    sorter: (a: FingerprintRecord, b: FingerprintRecord) => a.name.localeCompare(b.name),
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
    title: "平台",
    dataIndex: "platform",
    key: "platform",
    width: 110,
    filters: Array.from(new Set(records.map((r) => r.platform).filter(Boolean)))
      .sort()
      .map((platform) => ({ text: platform, value: platform })),
    onFilter: (value: unknown, record: FingerprintRecord) => record.platform === value,
  },
  {
    title: "JA4",
    dataIndex: "ja4",
    key: "ja4",
    render: (value: string) =>
      value ? (
        <span className="mono" style={{ fontSize: 12 }}>
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
    width: 100,
    render: (value: FingerprintRecord["fidelity"]) => <FidelityTag value={value} />,
  },
];

export function LibraryExplorer() {
  const [query, setQuery] = useState("");
  const [family, setFamily] = useState<string | undefined>();
  const [fidelity, setFidelity] = useState<"all" | "exact" | "other">("all");
  const [platform, setPlatform] = useState<string | undefined>();

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return records.filter((record) => {
      if (family && record.family !== family) return false;
      if (platform && record.platform !== platform) return false;
      if (fidelity === "exact" && record.fidelity !== "exact") return false;
      if (fidelity === "other" && record.fidelity === "exact") return false;
      if (!needle) return true;
      return (
        record.name.toLowerCase().includes(needle) ||
        record.client.toLowerCase().includes(needle) ||
        record.ja4.toLowerCase().includes(needle)
      );
    });
  }, [query, family, platform, fidelity]);

  return (
    <section className="section" id="library">
      <span className="section__kicker">内置指纹库</span>
      <h2 className="section__title">全部 {records.length} 条记录，全部来自抓包</h2>
      <Typography.Paragraph className="section__lede">
        每条记录都由真实客户端的一次握手做成，另有 {aliases.length} 个别名指向同一份线路参数。
        审计脚本会从记录所引用的抓包里重新计算一遍 JA4，算不出来的记录会让构建失败。
      </Typography.Paragraph>

      <div style={{ display: "flex", gap: 12, marginBottom: 18, flexWrap: "wrap" }}>
        <Input
          allowClear
          placeholder="搜索名称、客户端或 JA4"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          style={{ maxWidth: 340 }}
        />
        <Select
          allowClear
          placeholder="按家族筛选"
          options={families}
          value={family}
          onChange={(value) => setFamily(value)}
          style={{ minWidth: 200 }}
        />
        <Select
          allowClear
          placeholder="按平台筛选"
          options={platforms}
          value={platform}
          onChange={(value) => setPlatform(value)}
          style={{ minWidth: 160 }}
        />
        <Segmented
          value={fidelity}
          onChange={(value) => setFidelity(value as typeof fidelity)}
          options={[
            { label: "全部保真度", value: "all" },
            { label: "exact", value: "exact" },
            { label: "close / partial", value: "other" },
          ]}
        />
        <Tag bordered={false} style={{ alignSelf: "center" }}>
          匹配 {filtered.length} 条
        </Tag>
        {query || family || platform || fidelity !== "all" ? (
          <Button
            type="text"
            size="small"
            onClick={() => {
              setQuery("");
              setFamily(undefined);
              setPlatform(undefined);
              setFidelity("all");
            }}
          >
            清除筛选
          </Button>
        ) : null}
      </div>

      {filtered.length === 0 ? (
        <p className="library__empty">
          没有记录同时满足这些条件。放宽平台或保真度再看一次，或者{" "}
          <Link to="/clients">按客户端</Link>浏览。
        </p>
      ) : null}

      {filtered.length > 0 ? (
        <Table
          rowKey="name"
          size="small"
          columns={columns}
          dataSource={filtered}
          pagination={{ pageSize: 20, showSizeChanger: false }}
          scroll={{ x: 820 }}
        />
      ) : null}
    </section>
  );
}

import { useMemo, useState } from "react";
import { Input, Select, Table, Tag, Typography } from "antd";
import { aliases, records } from "../data/library";
import type { FingerprintRecord } from "../data/library";
import { FidelityTag } from "./FidelityTag";

// The whole built-in library, searchable. The list is generated from the
// crate, so what the site shows is what the library ships.

const families = Array.from(new Set(records.map((r) => r.family).filter(Boolean)).values())
  .sort()
  .map((family) => ({ label: family, value: family }));

const columns = [
  {
    title: "名称",
    dataIndex: "name",
    key: "name",
    render: (value: string) => <span className="mono">{value}</span>,
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

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return records.filter((record) => {
      if (family && record.family !== family) return false;
      if (!needle) return true;
      return (
        record.name.toLowerCase().includes(needle) ||
        record.client.toLowerCase().includes(needle) ||
        record.ja4.toLowerCase().includes(needle)
      );
    });
  }, [query, family]);

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
        <Tag bordered={false} style={{ alignSelf: "center" }}>
          匹配 {filtered.length} 条
        </Tag>
      </div>

      <Table
        rowKey="name"
        size="small"
        columns={columns}
        dataSource={filtered}
        pagination={{ pageSize: 20, showSizeChanger: false }}
        scroll={{ x: 820 }}
      />
    </section>
  );
}

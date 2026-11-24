import { Card, Col, Row, Table, Tag, Typography } from "antd";
import { androidGroups, androidRecordCount } from "../data/library";
import type { FingerprintRecord } from "../data/library";
import { FidelityTag } from "./FidelityTag";

// The Android section: every built-in Android record, grouped by the library
// that shapes the ClientHello. Each group states what the library is, then
// lists the versions with the JA4 taken from the record's own capture.

const columns = [
  {
    title: "记录",
    dataIndex: "name",
    key: "name",
    render: (value: string) => <span className="mono">{value}</span>,
  },
  {
    title: "版本",
    dataIndex: "version",
    key: "version",
    width: 150,
    render: (value: string) => value || "—",
  },
  {
    title: "JA4",
    dataIndex: "ja4",
    key: "ja4",
    // The hash is written on two lines so the whole table fits the card
    // without a horizontal scrollbar hiding the fidelity tag.
    render: (value: string) =>
      value ? (
        <span className="mono" style={{ fontSize: 12, lineHeight: 1.5 }}>
          {value.split("_")[0]}
          <br />
          {value.split("_").slice(1).join("_")}
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

export function AndroidLibraries() {
  return (
    <section className="section" id="android">
      <span className="section__kicker">Android 指纹</span>
      <h2 className="section__title">Android 上每种库、每个版本都实测过</h2>
      <Typography.Paragraph className="section__lede">
        {androidRecordCount} 条内置记录，覆盖 OkHttp、Conscrypt 平台栈、Cronet 与 WebView。
        每一条都对应一次真实 Android 运行时发出的 ClientHello —— Android 7.0、8.1、9、10、12、13、14
        的模拟器与容器，以及云手机 —— 并逐字节比对了 JA4 的三段。
      </Typography.Paragraph>

      <Row gutter={[20, 20]}>
        {androidGroups.map((group) => (
          <Col xs={24} xl={12} key={group.key}>
            <Card
              title={
                <span style={{ fontFamily: "var(--font-display)", fontSize: 19 }}>
                  {group.title}{" "}
                  <Tag bordered={false} style={{ marginLeft: 6 }}>
                    {group.records.length}
                  </Tag>
                </span>
              }
              bordered
              style={{ background: "var(--paper)", height: "100%" }}
            >
              <Typography.Paragraph
                type="secondary"
                style={{ fontSize: 13, lineHeight: 1.7, marginBottom: 12 }}
              >
                {group.blurb}
              </Typography.Paragraph>
              <Table
                size="small"
                rowKey="name"
                pagination={false}
                columns={columns}
                dataSource={group.records}
                
              />
            </Card>
          </Col>
        ))}
      </Row>
    </section>
  );
}

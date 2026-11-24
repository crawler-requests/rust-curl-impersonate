import { familySummary, totals } from "../data/library";
import { CodeBlock, Comment, Str } from "../components/CodeBlock";
import { LibraryExplorer } from "../components/LibraryExplorer";
import { FidelityBreakdown } from "../components/FidelityBreakdown";
import { SuiteFrequency } from "../components/SuiteFrequency";
import { PlatformSplit } from "../components/PlatformSplit";
import { familyIcon } from "../components/icons";

export function LibraryPage() {
  const maxFamily = familySummary[0]?.count ?? 1;

  return (
    <>
      <section className="hero hero--compact">
        <div className="hero__eyebrow">指纹库</div>
        <h1 className="hero__title">
          {totals.records} 条记录，
          <br />
          每一条都有<b>自己的抓包</b>。
        </h1>
        <p className="hero__lede">
          浏览器进程实测、官方 Docker 镜像抓到的各语言运行时、tls-client 的 ClientHello 定义并实测、
          uTLS 的旧版本定义，以及 Android 与 iOS 上的真实应用。另有 {totals.aliases} 个别名指向同一份线路参数。
        </p>
      </section>

      <LibraryExplorer />

      <section className="section">
        <span className="section__kicker">覆盖范围</span>
        <h2 className="section__title">按家族看记录数量</h2>
        <p className="section__lede">
          {totals.families} 个家族，分布很不均匀：Chrome 一家就占了三分之一，
          因为它每个大版本都要单独抓一次；运行时那一侧每个语言只留代表性的几个版本。
        </p>
        <div className="family-grid">
          {familySummary.map((family) => (
            <div className="family-tile" key={family.key}>
              <div className="family-tile__head">
                <span className="family-tile__icon" style={{ color: family.tint }}>
                  {familyIcon(family.key)}
                </span>
                <span className="family-tile__name">{family.label}</span>
              </div>
              <div className="family-tile__count">{family.count} 条记录</div>
              <div
                className="family-tile__bar"
                style={{
                  background: family.tint,
                  width: `${Math.max(18, (family.count / maxFamily) * 100)}%`,
                }}
              />
            </div>
          ))}
        </div>
      </section>

      <FidelityBreakdown />

      <SuiteFrequency />

      <PlatformSplit />

      <section className="section">
        <span className="section__kicker">怎么用</span>
        <h2 className="section__title">记录名就是 Profile::find 的参数</h2>
        <CodeBlock>
          {"let client = Client::new(Profile::find("}
          <Str>"go1.26"</Str>
          {")?)?;\nlet client = Client::new(Profile::find("}
          <Str>"python3.12_requests"</Str>
          {")?)?;\nlet client = Client::new(Profile::find("}
          <Str>"node22_http2"</Str>
          {")?)?;\n\n"}
          <Comment>{"// 记录里没有的头由调用方自己补；同名头替换默认头\n"}</Comment>
          {"let response = client.get("}
          <Str>"https://api.example.com"</Str>
          {")?.header("}
          <Str>"accept"</Str>
          {", "}
          <Str>"application/json"</Str>
          {").send().await?;\n"}
        </CodeBlock>
      </section>

    </>
  );
}

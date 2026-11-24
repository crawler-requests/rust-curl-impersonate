import { Link } from "react-router-dom";
import { FAMILY_PAGES, recordsOf } from "../data/families";
import { familyIcon } from "../components/icons";

// The directory of client families. The header menu offers the same six
// entries in one slot; this page is where a reader lands when they want the
// whole picture rather than one family's records.

export function ClientsPage() {
  return (
    <>
      <section className="hero hero--compact">
        <div className="hero__eyebrow">客户端</div>
        <h1 className="hero__title">
          {FAMILY_PAGES.length} 类客户端，
          <br />
          各有各的<b>握手</b>。
        </h1>
        <p className="hero__lede">
          指纹不是按「浏览器 / 非浏览器」分的，而是按发出 ClientHello 的那一层 TLS 实现分的。
          Chromium 的 BoringSSL、Firefox 的 NSS、Apple 的 SecureTransport、Android 上的
          Conscrypt 与 OkHttp，以及各语言运行时自带的栈，两两之间哈希都不同。
          下面每一类都有自己的记录，也都有一条主线说明它为什么与别人不一样。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">按客户端浏览</span>
        <h2 className="section__title">选一个家族，看它的记录</h2>
        <div className="client-card-grid">
          {FAMILY_PAGES.map((page) => {
            const all = recordsOf(page);
            const exact = all.filter((record) => record.fidelity === "exact").length;
            const close = all.filter((record) => record.fidelity !== "exact").length;
            // One record per distinct client, so the card shows the range
            // (Chrome / Edge / Brave, or NSURLSession / SwiftNIO / Safari) rather
            // than three versions of the same program.
            const seen = new Set<string>();
            const sample: string[] = [];
            for (const record of all) {
              if (seen.has(record.client)) continue;
              seen.add(record.client);
              sample.push(record.name);
              if (sample.length === 3) break;
            }

            return (
              <Link key={page.key} to={page.path} className="client-card">
                <div className="client-card__head">
                  <span className="client-card__icon">{familyIcon(page.members[0])}</span>
                  <span className="client-card__nav">{page.nav}</span>
                  <span className="client-card__count">{all.length} 条</span>
                </div>
                <span className="client-card__title">{page.title}</span>
                <span className="client-card__body">{page.lede}</span>
                {sample.length > 0 ? (
                  <span className="client-card__sample">
                    {sample.map((name) => (
                      <span className="client-card__sample-name mono" key={name}>
                        {name}
                      </span>
                    ))}
                  </span>
                ) : null}
                <span className="client-card__foot">
                  {close === 0
                    ? `${all.length} 条全部逐字节一致`
                    : `${exact} 条逐字节一致 · ${close} 条有偏差已注明`}
                  {page.members.length > 1 ? ` · ${page.members.length} 个家族共用这一页` : ""}
                </span>
              </Link>
            );
          })}
        </div>
      </section>

      <section className="section">
        <span className="section__kicker">怎么用这张表</span>
        <h2 className="section__title">先定客户端，再定版本</h2>
        <p className="section__lede">
          服务端看到的是握手，不是程序名。所以挑记录的顺序是：先选客户端家族，
          再在这个家族里挑一个与目标一致的版本。跨家族借用参数会让指纹变成两边都不像。
          不确定某个东西属于哪一类时，<Link to="/library">指纹库</Link> 页可以按名称或
          JA4 直接搜。
        </p>
      </section>
    </>
  );
}

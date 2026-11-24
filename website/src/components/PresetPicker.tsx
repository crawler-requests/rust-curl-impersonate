import { useMemo, useState } from "react";
import { Segmented } from "antd";
import { Link } from "react-router-dom";
import { handshakes } from "../data/handshakes";

// "Which name should I pass to Profile::find?" answered by the kind of target
// rather than by an alphabetical list. Each answer is a record the library
// actually ships, and clicking through lands on the family page that owns it.

const SCENARIOS = [
  { value: "browser", label: "要过浏览器风控" },
  { value: "runtime", label: "服务端在认语言版本" },
  { value: "mobile", label: "请求看起来来自手机" },
  { value: "h3", label: "要走 HTTP/3" },
];

const FAMILY_OF: Record<string, "browser" | "runtime" | "mobile"> = {
  chrome: "browser",
  firefox: "browser",
  safari: "browser",
  edge: "browser",
  brave: "browser",
  opera: "browser",
  "360": "browser",
  qq: "browser",
  android: "mobile",
  okhttp: "mobile",
  ios: "mobile",
  go: "runtime",
  python: "runtime",
  node: "runtime",
  php: "runtime",
  java: "runtime",
  dotnet: "runtime",
  ruby: "runtime",
  curl: "runtime",
  wget: "runtime",
  openssl: "runtime",
  rust: "runtime",
  perl: "runtime",
  erlang: "runtime",
  bun: "runtime",
  deno: "runtime",
  dart: "runtime",
  cloudflare: "runtime",
};

const ADVICE: Record<string, string> = {
  browser: "浏览器记录来自官方构建的真实进程。服务端如果比对 cipher 顺序或 GREASE 位置，只有这一组能对上。",
  runtime: "同一语言的不同版本常常只差一两个扩展。先确认对面认的是哪个版本，再选记录，别拿一个近似版本顶替。",
  mobile: "手机上的握手由系统版本和内置栈一起决定。同一台手机，OkHttp、平台 Conscrypt、WebView、Cronet 可以发出四种不同的握手。",
  h3: "带 QUIC 配置的记录可以和 HTTP/3 一起用。没有 QUIC 配置的记录要求只走 HTTP/3 会失败，不会悄悄退回 h2。",
};

export function PresetPicker() {
  const [scenario, setScenario] = useState("browser");

  const picks = useMemo(() => {
    if (scenario === "h3") {
      return handshakes.filter((handshake) => handshake.http3).slice(0, 6);
    }
    const inGroup = handshakes.filter((handshake) => FAMILY_OF[handshake.family] === scenario);
    // Walk the families in turn instead of sorting by name: the mobile group
    // is mostly Android, and a plain sort would fill every card with it and
    // hide that iOS has records too. Within a family, exact comes first.
    const byFamily = new Map<string, typeof inGroup>();
    for (const handshake of inGroup) {
      const list = byFamily.get(handshake.family) ?? [];
      list.push(handshake);
      byFamily.set(handshake.family, list);
    }
    for (const list of byFamily.values()) {
      list.sort((a, b) => {
        const byFidelity = Number(a.fidelity !== "exact") - Number(b.fidelity !== "exact");
        return byFidelity !== 0 ? byFidelity : b.version.localeCompare(a.version, undefined, { numeric: true });
      });
    }
    const out: typeof inGroup = [];
    const limit = 8;
    let row = 0;
    while (out.length < limit) {
      let added = false;
      for (const list of byFamily.values()) {
        if (out.length >= limit) break;
        if (row < list.length) {
          out.push(list[row]);
          added = true;
        }
      }
      if (!added || row > 4) break;
      row += 1;
    }
    return out;
  }, [scenario]);

  return (
    <section className="section picker">
      <div className="section__head">
        <span className="section__kicker">按场景挑</span>
        <h2 className="section__title">你要像谁，就从哪一组里挑</h2>
        <p className="section__lede">{ADVICE[scenario]}</p>
      </div>

      <Segmented
        className="picker__switch"
        value={scenario}
        onChange={(value) => setScenario(String(value))}
        options={SCENARIOS}
      />

      {scenario === "h3" ? (
        <div className="picker__presets">
          <span className="picker__presets-label">
            此外，这些 curl-impersonate 预设自带 QUIC 配置，可以直接用：
          </span>
          <div className="anatomy__tags">
            {["chrome145", "chrome146", "chrome150", "firefox147"].map((preset) => (
              <span className="anatomy__tag anatomy__tag--mono" key={preset}>
                {preset}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {picks.length === 0 ? (
        <p className="anatomy__aside">这一组目前没有可用的记录。</p>
      ) : (
        <div className="picker__grid">
          {picks.map((pick) => (
            <Link key={pick.name} to={`/${pick.family}`} className="picker__card">
              <span className="picker__name mono">{pick.name}</span>
              <span className="picker__client">{pick.client}</span>
              <span className="picker__meta">
                {pick.version || "—"}
                {pick.http3 ? " · 带 HTTP/3" : ""}
                {pick.fidelity !== "exact" ? ` · ${pick.fidelity}` : ""}
              </span>
            </Link>
          ))}
        </div>
      )}
    </section>
  );
}

import { useMemo } from "react";
import { records } from "../data/library";

// Where each record came from: which OS ran the client, and for mobile, which
// TLS library inside it shaped the hello. Both are read off the record fields,
// so the split moves when the library does.

const PLATFORM_LABEL: Record<string, string> = {
  linux: "Linux",
  windows: "Windows",
  macos: "macOS",
  android: "Android",
  ios: "iOS",
};

const LIBRARY_LABEL: Record<string, string> = {
  conscrypt: "Conscrypt",
  webkit: "WebKit",
  cfnetwork: "CFNetwork",
  webview: "WebView",
  cronet: "Cronet",
  "webkit-macos": "WebKit (macOS)",
  webkitgtk: "WebKitGTK",
  swiftnio: "SwiftNIO",
};

export function PlatformSplit() {
  const platforms = useMemo(() => {
    const counts = new Map<string, number>();
    for (const record of records) {
      const key = record.platform || "未标注";
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([key, count]) => ({ key, count, label: PLATFORM_LABEL[key] ?? key }))
      .sort((a, b) => b.count - a.count);
  }, []);

  const libraries = useMemo(() => {
    const counts = new Map<string, number>();
    for (const record of records) {
      if (!record.library) continue;
      counts.set(record.library, (counts.get(record.library) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([key, count]) => ({ key, count, label: LIBRARY_LABEL[key] ?? key }))
      .sort((a, b) => b.count - a.count);
  }, []);

  const total = records.length;

  return (
    <section className="section">
      <div className="section__head">
        <span className="section__kicker">记录从哪来</span>
        <h2 className="section__title">抓包发生在哪些系统上</h2>
        <p className="section__lede">
          同一套浏览器在 Linux 与 Windows 上抓出来的记录经常是一份，因为握手由浏览器自带的
          BoringSSL 决定；移动端则要按系统里的 TLS 库再分一次，同一个 Android 版本上四种库各有一条。
        </p>
      </div>

      <div className="split__grid">
        <div className="split__col">
          <div className="split__title">平台</div>
          {' '}
          {platforms.map((entry) => (
            <div className="split__row" key={entry.key}>
              <span className="split__label">{entry.label}</span>
              <span className="split__bar">
                <span className="split__fill" style={{ width: `${(entry.count / total) * 100}%` }} />
              </span>
              <span className="split__count mono">{entry.count}</span>
            </div>
          ))}
        </div>
        <div className="split__col">
          <div className="split__title">移动端 TLS 库</div>
          {libraries.map((entry) => (
            <div className="split__row" key={entry.key}>
              <span className="split__label">{entry.label}</span>
              <span className="split__bar">
                <span
                  className="split__fill split__fill--alt"
                  style={{ width: `${(entry.count / Math.max(...libraries.map((l) => l.count))) * 100}%` }}
                />
              </span>
              <span className="split__count mono">{entry.count}</span>
            </div>
          ))}
          {libraries.length === 0 ? <p className="split__empty">没有标注库的记录。</p> : null}
        </div>
      </div>
    </section>
  );
}

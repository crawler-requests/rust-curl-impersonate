import { useMemo, useState } from "react";
import { Segmented, Typography } from "antd";
import { records } from "../data/library";
import type { FingerprintRecord } from "../data/library";

// A ClientHello the visitor can change. JA4's a-segment is a count of ciphers
// and extensions, so switching those two currencies redraws the fingerprint in
// front of them: the bars change length and the hash changes with it.

const MONO_SAMPLE = 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256';

interface Variant {
  key: string;
  label: string;
  why: string;
  record: FingerprintRecord;
}

function pick(name: string): FingerprintRecord | undefined {
  return records.find((record) => record.name === name);
}

const VARIANTS: Variant[] = [
  {
    key: "android_webview125",
    label: "WebView 125",
    why: "Chromium 的栈：17 个扩展，带 ALPS 与 ECH GREASE，padding 由报文大小决定。",
  },
  {
    key: "android_conscrypt13",
    label: "平台 Conscrypt",
    why: "Android 自带的 TLS provider：多两个 ECDSA CBC 套件，ALPN 只给 http/1.1。",
  },
  {
    key: "android_okhttp13",
    label: "OkHttp 4.12",
    why: "OkHttp 走平台栈时是这套；13 个扩展，h2 与 http/1.1 都报。",
  },
  {
    key: "android_okhttp5",
    label: "OkHttp 5.0",
    why: "5.x 去掉了 session_ticket，扩展少一个，a 段从 t13d1513 变成 t13d1512。",
  },
  {
    key: "android_cronet76",
    label: "Cronet 76",
    why: "2020 年的 Chromium：没有 ALPS，套件多一个，a 段是 t13d1615。",
  },
]
  .map((spec) => ({ ...spec, record: pick(spec.key) }))
  .filter((variant): variant is Variant => Boolean(variant.record));

function segment(ja4: string, index: number): string {
  return ja4.split("_")[index] ?? "";
}

/** The a-segment reads t, version, d/i, cipher count, extension count, ALPN. */
function aParts(ja4: string) {
  const a = segment(ja4, 0);
  return {
    version: a.slice(1, 3),
    sni: a.slice(3, 4),
    ciphers: Number(a.slice(4, 6)),
    extensions: Number(a.slice(6, 8)),
    alpn: a.slice(8),
  };
}

export function HelloExplorer() {
  const [selected, setSelected] = useState<string>(VARIANTS[0]?.key ?? "");
  const variant = VARIANTS.find((item) => item.key === selected) ?? VARIANTS[0];

  const shape = useMemo(() => aParts(variant.record.ja4), [variant]);

  const maxCiphers = Math.max(...VARIANTS.map((item) => aParts(item.record.ja4).ciphers));
  const maxExtensions = Math.max(...VARIANTS.map((item) => aParts(item.record.ja4).extensions));

  return (
    <section className="section hello-explorer" id="hello">
      <div className="section__head">
        <span className="section__kicker">同一个系统，不同的握手</span>
        <h2 className="section__title">换一个库，指纹就换了一组数字</h2>
        <Typography.Paragraph className="section__lede">
          下面都是 Android 13 上的真实抓包。切换库，看 a 段的套件与扩展计数怎么走，
          以及它把 JA4 的尾部哈希带到哪里去。
        </Typography.Paragraph>
      </div>

      <Segmented
        className="hello-explorer__switch"
        value={selected}
        onChange={(value) => setSelected(String(value))}
        options={VARIANTS.map((item) => ({ label: item.label, value: item.key }))}
      />

      <div className="hello-explorer__body">
        <div className="hello-explorer__why">{variant.why}</div>

        <div className="hello-explorer__ja4">
          <span className="hello-explorer__ja4-a">{segment(variant.record.ja4, 0)}</span>
          <span className="hello-explorer__sep">_</span>
          <span>{segment(variant.record.ja4, 1)}</span>
          <span className="hello-explorer__sep">_</span>
          <span>{segment(variant.record.ja4, 2)}</span>
        </div>

        <div className="hello-explorer__bars">
          <div className="bar-row">
            <span className="bar-row__label">套件</span>
            <span className="bar-track">
              <span
                className="bar-fill"
                style={{ width: `${(shape.ciphers / maxCiphers) * 100}%` }}
              />
            </span>
            <span className="bar-row__value">{shape.ciphers}</span>
          </div>
          <div className="bar-row">
            <span className="bar-row__label">扩展</span>
            <span className="bar-track">
              <span
                className="bar-fill bar-fill--ext"
                style={{ width: `${(shape.extensions / maxExtensions) * 100}%` }}
              />
            </span>
            <span className="bar-row__value">{shape.extensions}</span>
          </div>
          <div className="hello-explorer__facts">
            <span>TLS {shape.version === "13" ? "1.3" : "1.2"}</span>
            <span>{shape.sni === "d" ? "带 SNI" : "不带 SNI"}</span>
            <span>ALPN {shape.alpn || "00"}</span>
          </div>
        </div>
      </div>

      <div className="hello-explorer__sample">
        <span className="hello-explorer__sample-label">其中一个签名算法列表（真实抓包）</span>
        <span className="mono">{MONO_SAMPLE}</span>
      </div>
    </section>
  );
}

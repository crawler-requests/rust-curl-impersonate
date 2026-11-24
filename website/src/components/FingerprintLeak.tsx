import { useState } from "react";
import { Segmented } from "antd";
import { handshakeFor } from "../data/handshakes";
import { extensionLabel } from "../data/extensions";

// The page's central claim, made switchable: a request that only changes its
// User-Agent still sends its own ClientHello, and this panel shows exactly
// which fields give it away.

const MODES = [
  { value: "ua", label: "只改 User-Agent" },
  { value: "full", label: "连握手一起改" },
];

// The "before" side is not invented: it is the Go record the library ships,
// which sends the short OpenSSL-era list with no GREASE, ECH or ALPS. Any
// client that only swaps its User-Agent looks like this on the wire.
const plain = handshakeFor("go1.26");
const PLAIN = {
  ciphers: plain?.ciphers.length ?? 13,
  extensions: plain?.extensionOrder.length ?? 10,
  grease: plain?.grease ?? false,
  alps: plain?.alps ?? false,
  ech: plain?.echGrease ?? false,
  permute: plain?.permuteExtensions ?? false,
};

export function FingerprintLeak() {
  const [mode, setMode] = useState("ua");
  const chrome = handshakeFor("chrome158");
  const full = mode === "full";

  const compare = [
    { label: "cipher 数量", plain: PLAIN.ciphers, target: chrome?.ciphers.length ?? PLAIN.ciphers },
    { label: "命名组", plain: plain?.curves.length ?? 5, target: chrome?.curves.length ?? 5 },
    {
      label: "扩展数量",
      plain: PLAIN.extensions,
      target: chrome?.extensionOrder.length ?? PLAIN.extensions,
    },
    { label: "GREASE", plain: false, target: chrome?.grease ?? false },
    { label: "ECH GREASE", plain: false, target: chrome?.echGrease ?? false },
    { label: "ALPS", plain: false, target: chrome?.alps ?? false },
    { label: "扩展每次重排", plain: false, target: chrome?.permuteExtensions ?? false },
  ];

  return (
    <section className="section leak" id="leak">
      <div className="section__head">
        <span className="section__kicker">抓包会看到什么</span>
        <h2 className="section__title">改的到底是哪一层</h2>
        <p className="section__lede">
          请求头里的 User-Agent 是一个字符串，改它不需要理解任何东西。
          握手是另一回事：它由 TLS 实现决定，一个库只会发自己那一种。
          下面切换一下，看同一段代码在抓包里长什么样。
        </p>
      </div>

      <Segmented
        className="leak__switch"
        value={mode}
        onChange={(value) => setMode(String(value))}
        options={MODES}
      />

      <div className="leak__body">
        <div className="leak__col">
          <div className="leak__col-head">
            <span>你的请求</span>
            <span className="mono">requests::get(url)</span>
          </div>
          <ul className="leak__facts">
            <li>
              <span>User-Agent</span>
              <span className={`mono${full ? " leak__ok" : " leak__bad"}`}>
                {full ? "Chrome/158.0.8127.18" : "chrome/1.0"}
              </span>
            </li>
            <li>
              <span>cipher 列表</span>
              <span className={`mono${full ? " leak__ok" : " leak__bad"}`}>
                {full && chrome ? chrome.ciphers.length : PLAIN.ciphers} 个
              </span>
            </li>
            <li>
              <span>扩展顺序</span>
              <span className={`mono${full ? " leak__ok" : " leak__bad"}`}>
                {full && chrome
                  ? `${chrome.extensionOrder.length} 个，与抓包一致`
                  : `${PLAIN.extensions} 个，非浏览器形态`}
              </span>
            </li>
          </ul>
        </div>

        <div className="leak__col">
          <div className="leak__col-head">
            <span>服务端看到的握手</span>
            <span className="mono">JA4 / JA3 / Akamai</span>
          </div>
          <ul className="leak__compare">
            {compare.map((row) => (
              <li key={row.label}>
                <span className="leak__compare-label">{row.label}</span>
                <span className={`leak__compare-value${full ? " leak__ok" : " leak__bad"}`}>
                  {typeof row.plain === "boolean"
                    ? row.plain
                      ? "带"
                      : "不带"
                    : row.plain}
                </span>
                <span className="leak__arrow">→</span>
                <span className={`leak__compare-value${full ? " leak__ok" : ""}`}>
                  {typeof row.target === "boolean"
                    ? row.target
                      ? "带"
                      : "不带"
                    : row.target}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {full && chrome ? (
        <div className="leak__reveal">
          <span className="leak__reveal-label">
            这一层里真正决定指纹的扩展，按 Chrome 158 的顺序：
          </span>
          <div className="anatomy__tags">
            {chrome.extensionOrder
              .filter((id) => ["4832", "51764", "65037", "17613", "17513", "41", "27", "28"].includes(id))
              .map((id) => (
                <span className="anatomy__tag anatomy__tag--mono" key={id}>
                  {id} {extensionLabel(id).name}
                </span>
              ))}
          </div>
        </div>
      ) : (
        <p className="leak__note">
          这时服务端看到的是一个 Rust/OpenSSL 形态的 ClientHello。User-Agent 写着 chrome，
          握手却不像任何一个浏览器，两者对不上本身就是可疑信号。
        </p>
      )}
    </section>
  );
}

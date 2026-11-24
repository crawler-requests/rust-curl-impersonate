import { useState } from "react";
import { PlusOutlined, MinusOutlined } from "@ant-design/icons";
import { Link } from "react-router-dom";
import { totals } from "../data/library";
import { handshakeTotals } from "../data/handshakes";

// The questions a reader has after the pitch, answered where they are asked.
// Each answer points at the page that holds the full version.

interface Item {
  q: string;
  a: React.ReactNode;
}

const ITEMS: Item[] = [
  {
    q: "这和直接改 User-Agent、加几个请求头有什么区别？",
    a: (
      <>
        改请求头只影响 HTTP 层。服务端判定客户端时看的是 TLS 握手里的 cipher 顺序、扩展顺序、
        GREASE 位置与 ALPS/ECH 码点，这些由 TLS 实现决定，请求头改再多也碰不到。
        <Link to="/problem">解决什么问题</Link> 页有一段可切换的对比。
      </>
    ),
  },
  {
    q: "为什么不直接用 rustls？",
    a: (
      <>
        rustls 的 API 刻意收窄，不暴露 cipher 顺序、扩展顺序、GREASE、ECH、ALPS 与证书压缩。
        这正是 JA3/JA4 用来区分客户端的东西。能拼出浏览器 ClientHello 的只有 BoringSSL，
        本库保留 curl-impersonate 的这一半，并在上面重写 curl 那一层。
      </>
    ),
  },
  {
    q: `库里 ${totals.records} 条记录都是真的抓包吗？`,
    a: (
      <>
        是。每条记录都指向 <span className="mono">tools/capture/raw/</span> 下的一次握手，
        审计脚本从那个文件重算 JA4，对不上就让 CI 失败。
        共 {handshakeTotals.ciphers} 条 cipher 条目、{handshakeTotals.extensions} 条扩展顺序条目被逐条核对过。
        <Link to="/evidence">可信度</Link> 页有审计输出。
      </>
    ),
  },
  {
    q: "记录标 close 或 partial，还能用吗？",
    a: (
      <>
        能用，但要先看差额是什么。标 close 的记录只缺一两项（比如某个 OpenSSL 系的 DHE 套件），
        多数服务端不认这一项，指纹照样对得上；标 partial 的记录缺得比较多，形状已经明显不同，
        更适合对照而不是冒充。<Link to="/library">指纹库</Link> 可以按保真度筛。
      </>
    ),
  },
  {
    q: "要过 HTTP/3 的服务端怎么办？",
    a: (
      <>
        选带 QUIC 配置的记录或预设。没有 QUIC 配置的记录要求只走 HTTP/3 会直接失败，
        不会悄悄退回 h2。<Link to="/usage">用法</Link> 页按场景列了可用的名字。
      </>
    ),
  },
  {
    q: "Android 上一个版本为什么要抓那么多条？",
    a: (
      <>
        Android 上平台 Conscrypt、应用自带的 OkHttp、Cronet 与系统 WebView 是不同的 TLS 栈，
        同一个系统版本上能发出四种完全不同的握手。所以每条都单独抓、单独复核。
        <Link to="/android">Android</Link> 页有四条并排的对比。
      </>
    ),
  },
];

export function Faq() {
  const [open, setOpen] = useState<number | null>(0);

  return (
    <section className="section faq">
      <div className="section__head">
        <span className="section__kicker">常见问题</span>
        <h2 className="section__title">读完首页之后会问的六件事</h2>
      </div>
      <div className="faq__list">
        {ITEMS.map((item, index) => {
          const expanded = open === index;
          return (
            <div className={`faq__item${expanded ? " is-open" : ""}`} key={item.q}>
              <button
                type="button"
                className="faq__q"
                aria-expanded={expanded}
                aria-controls={`faq-answer-${index}`}
                onClick={() => setOpen(expanded ? null : index)}
              >
                <span>{item.q}</span>
                {expanded ? <MinusOutlined /> : <PlusOutlined />}
              </button>
              {expanded ? (
                <div className="faq__a" id={`faq-answer-${index}`}>
                  {item.a}
                </div>
              ) : null}
            </div>
          );
        })}
      </div>
    </section>
  );
}

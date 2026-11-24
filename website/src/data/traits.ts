// What a family's ClientHello is recognisable by. One entry per family owner;
// the page shows three, which is what a reader can hold.
//
// These are facts about the TLS stacks, not about the records: they explain
// why two families with the same version number still differ.

export interface Trait {
  title: string;
  body: string;
}

const TRAITS: Record<string, Trait[]> = {
  chrome: [
    {
      title: "扩展顺序每次都会变",
      body: "Chromium 为每次连接重新排列扩展列表，所以同一个版本两次握手扩展顺序不同，但集合与签名算法列表固定。记录里打开 permute_extensions 才是这个行为。",
    },
    {
      title: "GREASE 出现在四个位置",
      body: "cipher、group、version 与扩展列表各有一个 GREASE 值，且每次随机。它在 JA4 里被忽略，但在 JA3 与原始报文里是固定的形状。",
    },
    {
      title: "ALPS 与 ECH GREASE",
      body: "Chromium 会带上 application_settings，并在较新的版本里用随机长度的 ECH GREASE 占位；后者改变报文长度，进而决定是否触发 padding。",
    },
  ],
  firefox: [
    {
      title: "用 NSS，不是 BoringSSL",
      body: "Firefox 的 TLS 由 NSS 实现：扩展顺序固定、GREASE 只出现在 cipher 列表开头。这让它与 Chromium 系列的哈希总是不同。",
    },
    {
      title: "能让服务端发 ECH",
      body: "较新的 Firefox 支持真正的 ECH，并在 key_share 里带混合组；版本间的差异主要在这里，而不在 cipher 列表。",
    },
    {
      title: "delegated credentials",
      body: "Firefox 会请求 delegated credentials，Chromium 不会。这一条在 JA4 的 c 段里能看出来。",
    },
  ],
  safari: [
    {
      title: "走 SecureTransport",
      body: "Safari 的握手由 Apple 的 SecureTransport 产生，扩展集比 Chromium 小，没有 GREASE、ALPS 或 delegated credentials。",
    },
    {
      title: "平台与版本一起变",
      body: "同一 Safari 版本在 macOS、iOS 与 iPad 上可能不同，因为底层 SecureTransport 的版本不同。记录按平台分别抓。",
    },
    {
      title: "WebKitGTK 是另一套",
      body: "WebKitGTK 是 WebKit 在 Linux 上的构建，走 GnuTLS，握手与苹果平台上的 Safari 没有关系。",
    },
  ],
  ios: [
    {
      title: "应用大多走 NSURLSession",
      body: "iOS 应用的请求大多交给 NSURLSession，握手由 SecureTransport 产生，所以同一版本 iOS 上多数应用的指纹相同。",
    },
    {
      title: "自有栈的应用是个例外",
      body: "打包了 SwiftNIO 之类自有栈的应用会发出完全不同的握手，记录里单独列出。",
    },
    {
      title: "版本差异很小",
      body: "iOS 大版本之间常见的是 TLS 1.3 套件与组列表的微调，通过 a 段的计数与 c 段能区分。",
    },
  ],
  android: [
    {
      title: "同一个版本，四条栈",
      body: "平台 Conscrypt、应用自带的 OkHttp、Cronet 与系统 WebView 在同一个 Android 版本上各自不同，不能拿一个代表全部。",
    },
    {
      title: "应用可以换掉平台的 TLS",
      body: "Conscrypt 可以作为 JCA provider 被装进应用，OkHttp 也自带 BoringSSL。同一个手机上两个应用的指纹可以完全不同。",
    },
    {
      title: "padding 由报文大小决定",
      body: "BoringSSL 把 256–511 字节的向量补到 508 字节，所以 padding 的长度取决于当前 SNI 与扩展集，而不是某个版本固定写死。",
    },
  ],
  runtimes: [
    {
      title: "握手由那个实现决定",
      body: "Go 用 crypto/tls、Node 用 BoringSSL、Python 的 requests 用 OpenSSL、.NET 用 SChannel 或 OpenSSL。选记录名时其实是选那个实现。",
    },
    {
      title: "版本之间只差一两个扩展",
      body: "Go 1.20 与 1.26 主要是 cipher 列表与组的增加；Python 各版本差异在键共享与 TLS 1.3 的顺序。这些在 c 段里都能看出来。",
    },
    {
      title: "命令行工具也在这",
      body: "curl、wget、OpenSSL s_client 的握手同样可以被记录，很多爬虫与运维脚本用的就是它们。",
    },
  ],
};

export function traitsFor(members: string[]): Trait[] {
  for (const member of members) {
    const found = TRAITS[member];
    if (found) return found;
  }
  return [];
}

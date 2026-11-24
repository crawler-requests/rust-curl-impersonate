import { aliases, records } from "./library";
import type { FingerprintRecord } from "./library";

// The navigation is organised by client family, because that is how someone
// arrives: "I need to look like Chrome", not "I need record number 47". Each
// family gets a page with its own records; every family in the library is a
// member of exactly one of these pages, so nothing is unreachable.

export interface FamilyPage {
  key: string;
  /** Route path, e.g. "/chrome". */
  path: string;
  /** Nav label, kept short so six fit on one line. */
  nav: string;
  title: string;
  /** One sentence naming what this family is and why it differs from the rest. */
  lede: string;
  /** The families this page owns. `other` collects everything not listed. */
  members: string[];
}

export const FAMILY_PAGES: FamilyPage[] = [
  {
    key: "chrome",
    path: "/chrome",
    nav: "Chrome",
    title: "Chrome 与 Chromium",
    lede: "Chromium 的 TLS 栈被 Chrome、Edge、Brave、Opera 和 Android 的 WebView 共用，所以它的握手是这个生态里最常见的一种。每个大版本都会调整扩展顺序、GREASE 位置以及 ECH 与 ALPS 的码点。",
    members: ["chrome", "edge", "brave", "opera", "360", "qq"],
  },
  {
    key: "firefox",
    path: "/firefox",
    nav: "Firefox",
    title: "Firefox",
    lede: "Firefox 用自己的 NSS，不是 BoringSSL：扩展顺序固定、允许 ECH、支持 delegated credentials。它的握手因此与 Chromium 系列完全不同，Firefox 各版本之间也常有小的变动。",
    members: ["firefox"],
  },
  {
    key: "safari",
    path: "/safari",
    nav: "Safari",
    title: "Safari 与 Apple 的浏览器栈",
    lede: "Safari 走 Apple 的 SecureTransport；macOS、iOS、iPad 上的 Safari 在同一版本下也可能不同。WebKitGTK 是 WebKit 在 Linux 上的另一套构建。",
    members: ["safari"],
  },
  {
    key: "ios",
    path: "/ios",
    nav: "iOS",
    title: "iOS 应用与 NSURLSession",
    lede: "iOS 应用里的请求大多走 NSURLSession，握手由 SecureTransport 决定；也有一些应用自带 SwiftNIO 之类的栈。同一版本 iOS 上，不同应用可能发出不同的 ClientHello。",
    members: ["ios"],
  },
  {
    key: "android",
    path: "/android",
    nav: "Android",
    title: "Android",
    lede: "Android 平台的 TLS provider（Conscrypt）、应用自带的 OkHttp、Chromium 网络栈打包成的 Cronet，以及系统 WebView。同一个 Android 版本上，这四个可能发出完全不同的握手。",
    members: ["android", "okhttp"],
  },
  {
    key: "runtimes",
    path: "/runtimes",
    nav: "运行时",
    title: "服务端的命令行与运行时",
    lede: "服务端最常见的不是浏览器，而是语言运行时和命令行工具：Go、Python、Node、PHP、Java、.NET、Ruby、curl、wget、OpenSSL。它们大多用自己的 TLS 实现，握手由那个实现决定。",
    members: [
      "go",
      "python",
      "node",
      "php",
      "java",
      "dotnet",
      "ruby",
      "curl",
      "wget",
      "openssl",
      "rust",
      "perl",
      "erlang",
      "bun",
      "deno",
      "dart",
      "cloudflare",
    ],
  },
];

export function recordsOf(page: FamilyPage): FingerprintRecord[] {
  return records
    .filter((record) => page.members.includes(record.family))
    .sort((a, b) => {
      const byFamily = a.family.localeCompare(b.family);
      return byFamily !== 0 ? byFamily : a.name.localeCompare(b.name);
    });
}

/** Aliases whose base record belongs to this family, for the page's footnote. */
export function aliasesOf(page: FamilyPage): { name: string; target: string }[] {
  const names = new Set(recordsOf(page).map((record) => record.name));
  return aliases.filter((alias) => names.has(alias.target));
}

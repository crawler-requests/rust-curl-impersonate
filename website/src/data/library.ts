import raw from "./records.json";

// The dataset is generated from the crate by scripts/sync-library.mjs, so the
// site never drifts from what the library actually ships.

export type Fidelity = "exact" | "close" | "partial" | "";

export interface FingerprintRecord {
  name: string;
  family: string;
  client: string;
  version: string;
  platform: string;
  library: string;
  fidelity: Fidelity;
  source: string;
  ja4: string;
  http1Only: boolean;
  deviations: string[];
}

export interface Alias {
  name: string;
  target: string;
}

export const dataset = raw as unknown as {
  generatedFrom: string;
  baseRecords: number;
  aliases: number;
  records: FingerprintRecord[];
  aliasList: Alias[];
};

export const records = dataset.records;
export const aliases = dataset.aliasList;

/** Android-only view of the records, grouped by the library that shapes the hello. */
export interface AndroidGroup {
  key: string;
  title: string;
  blurb: string;
  /** The Android releases this group's records were captured on. */
  versions: string;
  records: FingerprintRecord[];
}

const isAndroid = (record: FingerprintRecord) =>
  record.platform === "android" ||
  record.family === "android" ||
  record.family === "okhttp" ||
  record.name.includes("android") ||
  record.name.includes("cronet");

const androidRecords = records.filter(isAndroid);

const group = (
  key: string,
  title: string,
  blurb: string,
  versions: string,
  pick: (r: FingerprintRecord) => boolean,
): AndroidGroup => ({
  key,
  title,
  blurb,
  versions,
  records: androidRecords.filter(pick).sort((a, b) => a.name.localeCompare(b.name)),
});

export const androidGroups: AndroidGroup[] = [
  group(
    "okhttp",
    "OkHttp",
    "Android 上最常见的应用层 HTTP 库。TLS 由它自带的 BoringSSL 或平台 Conscrypt 提供，握手形态随库版本和 Android 版本一起变化。",
    "Android 7.0、8.1、9、10、13",
    (r) => r.name.includes("okhttp") && !r.name.startsWith("utls"),
  ),
  group(
    "conscrypt",
    "Conscrypt / 平台 TLS",
    "Android 平台自带的 TLS provider，也是 HttpsURLConnection 的底层实现。应用可以把不同版本的 Conscrypt 装成 JCA provider 来换掉平台栈。",
    "Android 9、10、13",
    (r) => r.library === "conscrypt" && !r.name.includes("okhttp"),
  ),
  group(
    "cronet",
    "Cronet",
    "Chromium 的网络栈以库的形式打包进应用。它的握手形态与 WebView 同源，跨版本变化很少。",
    "Android 8.1 到 14",
    (r) => r.library === "cronet" || r.name.includes("cronet"),
  ),
  group(
    "webview",
    "WebView",
    "系统 WebView 使用 Chromium 的 TLS 栈。不同版本会在 ALPS 码点、padding 与 ECH GREASE 上不同。",
    "Android 10、11、13",
    (r) => r.library === "webview",
  ),
];

export const androidRecordCount = androidRecords.length;

export const androidFidelity = {
  exact: androidRecords.filter((r) => r.fidelity === "exact").length,
  close: androidRecords.filter((r) => r.fidelity === "close").length,
};

/** Families for the general library, with counts and a readable label. */
const FAMILY_LABELS: Record<string, string> = {
  chrome: "Chrome",
  firefox: "Firefox",
  safari: "Safari",
  ios: "iOS 应用与 NSURLSession",
  android: "Android 应用",
  okhttp: "OkHttp",
  python: "Python",
  go: "Go",
  curl: "curl",
  java: "Java / JVM",
  node: "Node.js",
  php: "PHP",
  openssl: "OpenSSL s_client",
  opera: "Opera",
  wget: "GNU Wget",
  edge: "Edge",
  "360": "360 浏览器",
  dotnet: ".NET",
  bun: "Bun",
  perl: "Perl",
  ruby: "Ruby",
  rust: "Rust",
  brave: "Brave",
  deno: "Deno",
  dart: "Dart",
  erlang: "Erlang",
  cloudflare: "Cloudflare",
  qq: "QQ 浏览器",
};

// A short accent per family, used for the family tiles and the library table's
// family column. Kept muted so the single orange stays the only loud colour.
const FAMILY_TINTS: Record<string, string> = {
  chrome: "#c78b5e",
  firefox: "#c4603c",
  safari: "#6f8f92",
  ios: "#8a8f86",
  android: "#b08a4a",
  okhttp: "#9a8b63",
  python: "#6f8f5a",
  go: "#4e8b9a",
  curl: "#a08a5e",
  java: "#9a6a5e",
  node: "#5a8f6f",
  php: "#7a6f9a",
  openssl: "#8a8068",
  opera: "#a0606a",
  rust: "#a0603c",
};

export const familySummary = Array.from(
  records.reduce((map, record) => {
    const key = record.family || "other";
    map.set(key, (map.get(key) ?? 0) + 1);
    return map;
  }, new Map<string, number>()),
)
  .map(([key, count]) => ({
    key,
    label: FAMILY_LABELS[key] ?? key,
    count,
    tint: FAMILY_TINTS[key] ?? "#e6e2d8",
  }))
  .sort((a, b) => b.count - a.count);

/** Clipboard-friendly totals shown in the hero. */
export const totals = {
  records: records.length,
  families: familySummary.length,
  android: androidRecordCount,
  aliases: aliases.length,
  presets: 48,
  exact: records.filter((record) => record.fidelity === "exact").length,
};

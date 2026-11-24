import raw from "./handshakes.json";
import type { Fidelity } from "./library";

// The wire-level view of each record: the cipher list, extension order, groups,
// signature algorithms and the opening HTTP/2 frame. Generated from the crate
// by scripts/sync-handshakes.mjs, so it is the same data the library sends.

export interface H2Setting {
  id: string;
  value: string;
}

export interface Http2Opening {
  settings: H2Setting[];
  pseudoOrder: string;
  windowUpdate: number | null;
  initialWindowSize: number | null;
}

export interface Handshake {
  name: string;
  family: string;
  client: string;
  version: string;
  platform: string;
  fidelity: Fidelity;
  /** JA4 of the capture, empty when the capture was a local socket. */
  ja4: string;
  /** The capture file this record was read from, shown as the record's evidence. */
  source: string;
  minVersion: string;
  maxVersion: string;
  alpn: string[];
  ciphers: string[];
  extensionOrder: string[];
  curves: string[];
  keyShares: string[];
  sigalgs: string[];
  grease: boolean;
  permuteExtensions: boolean;
  echGrease: boolean;
  alps: boolean;
  /** Number of delegated-credential signature algorithms offered. */
  delegatedCredentials: number;
  certCompression: string[];
  padding: string;
  http2: Http2Opening | null;
  http3: boolean;
  /** Fields the capture had that BoringSSL cannot send, named in the record. */
  deviations: string[];
}

const dataset = raw as unknown as {
  generatedFrom: string;
  records: number;
  counts: { ciphers: number; extensions: number; curves: number; sigalgs: number };
  handshakes: Handshake[];
};

export const handshakes = dataset.handshakes;

/** Totals across every record, for the "how much was captured" figures. */
export const handshakeTotals = dataset.counts;

const BY_NAME = new Map(handshakes.map((handshake) => [handshake.name, handshake]));

export function handshakeFor(name: string): Handshake | undefined {
  return BY_NAME.get(name);
}

/** Cipher suites grouped by what they are, for the length of the list. */
export function cipherKind(suite: string): "tls13" | "chacha" | "cbc" | "dhe" | "rsa" | "gcm" {
  if (suite.startsWith("TLS_AES_") || suite.startsWith("TLS_CHACHA20_POLY1305")) return "tls13";
  if (suite.includes("CBC")) return "cbc";
  if (suite.startsWith("TLS_DHE")) return "dhe";
  if (suite.startsWith("TLS_RSA_WITH")) return "rsa";
  if (suite.includes("CHACHA20")) return "chacha";
  return "gcm";
}

/** What actually differs between records: a short, mechanical summary. */
export interface Difference {
  label: string;
  from: string;
  to: string;
}

function shortList(value: string[]): string {
  return value.length <= 3 ? value.join("、") : `${value.length} 个`;
}

/**
 * The differences between two records of the same family, worked out rather
 * than written down: cipher count, extension set, key shares, ALPN, the
 * HTTP/2 settings. Each line names a field a server could fingerprint, so a
 * reader can see whether a version bump matters for their target.
 */
export function differencesBetween(a: Handshake, b: Handshake): Difference[] {
  const out: Difference[] = [];
  if (a.ciphers.length !== b.ciphers.length) {
    out.push({ label: "cipher 数量", from: String(a.ciphers.length), to: String(b.ciphers.length) });
  } else if (a.ciphers.join() !== b.ciphers.join()) {
    out.push({ label: "cipher 顺序", from: "不同", to: "不同" });
  }
  // Each side lists what the other lacks, so the row reads "mine has X that
  // yours does not" rather than a direction-dependent "少了/多了".
  const onlyInA = a.extensionOrder.filter((id) => !b.extensionOrder.includes(id));
  const onlyInB = b.extensionOrder.filter((id) => !a.extensionOrder.includes(id));
  if (onlyInA.length || onlyInB.length) {
    out.push({
      label: "独家扩展",
      from: onlyInA.length ? `有 ${onlyInA.join("、")}` : "—",
      to: onlyInB.length ? `有 ${onlyInB.join("、")}` : "—",
    });
  }
  if (a.keyShares.join() !== b.keyShares.join()) {
    out.push({ label: "key share", from: shortList(a.keyShares), to: shortList(b.keyShares) });
  }
  if (a.alpn.join() !== b.alpn.join()) {
    out.push({ label: "ALPN", from: a.alpn.join(",") || "无", to: b.alpn.join(",") || "无" });
  }
  for (const flag of ["grease", "echGrease", "alps", "permuteExtensions"] as const) {
    if (a[flag] !== b[flag]) {
      out.push({ label: flag, from: a[flag] ? "带" : "不带", to: b[flag] ? "带" : "不带" });
    }
  }
  if (a.http2 && b.http2 && a.http2.settings.map((s) => `${s.id}:${s.value}`).join(";") !== b.http2.settings.map((s) => `${s.id}:${s.value}`).join(";")) {
    out.push({ label: "HTTP/2 SETTINGS", from: "不同", to: "不同" });
  }
  if (!out.length) out.push({ label: "线路参数", from: "一致", to: "一致" });
  return out;
}

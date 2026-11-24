// Extracts the parts of each built-in record a reader can look at: the handshake
// a client actually sends, and the HTTP/2 frame it opens with.
//
// This is a build-time script, not site code. It reads the crate's
// src/fingerprint/builtin.json (and, for the JA4, the capture each record
// names) and writes src/data/handshakes.json, which the site imports. Run it
// after changing the library:
//
//   node scripts/sync-handshakes.mjs

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const OUT = join(HERE, "..", "src", "data", "handshakes.json");

const library = JSON.parse(
  readFileSync(join(ROOT, "src", "fingerprint", "builtin.json"), "utf8"),
).fingerprints.filter((record) => !record.extends);

const list = (value, separator) =>
  typeof value === "string" && value
    ? value.split(separator).filter(Boolean)
    : [];

const flag = (value) => value === "True" || value === true;

/** `1:65536;2:0;4:6291456` → the settings a server reads first. */
function settings(value) {
  if (!value) return [];
  return String(value)
    .split(";")
    .map((part) => {
      const [id, number] = part.split(":");
      return id ? { id, value: number ?? "0" } : null;
    })
    .filter(Boolean);
}

/** The capture's JA4 and the raw hash inputs behind it, for the anatomy panel. */
function ja4Of(record) {
  const source = record.source || "";
  const at = source.indexOf("tools/capture/raw/");
  if (at < 0) return { ja4: "", ja4r: "" };
  const file = source.slice(at + "tools/capture/raw/".length).split(/[\s,]+/)[0];
  try {
    const capture = JSON.parse(
      readFileSync(join(ROOT, "tools", "capture", "raw", file), "utf8"),
    );
    return { ja4: capture.tls?.ja4 || "", ja4r: capture.tls?.ja4_r || "" };
  } catch {
    return { ja4: "", ja4r: "" };
  }
}

const handshakes = library
  .filter((record) => record.tls && record.tls.ciphers)
  .map((record) => {
    const tls = record.tls ?? {};
    const h2 = record.http2 ?? {};
    return {
      name: record.name,
      family: record.family || "",
      client: record.client || "",
      version: record.version || "",
      platform: record.platform || "",
      source: record.source || "",
      fidelity: record.fidelity || "",
      ...ja4Of(record),
      minVersion: tls.min_version || "",
      maxVersion: tls.max_version || "",
      // `alpn` is already an array in builtin.json; older records store a
      // Python-repr string, so both shapes are accepted.
      alpn: Array.isArray(tls.alpn)
        ? tls.alpn.map(String)
        : list(String(tls.alpn ?? "").replace(/[\[\]'"]/g, ""), ",",
        ).map((item) => item.trim()),
      ciphers: list(tls.ciphers, ":"),
      extensionOrder: list(tls.extension_order, "-"),
      curves: list(tls.curves, ":"),
      keyShares: list(tls.key_shares, ":"),
      sigalgs: list(tls.sigalgs, ":"),
      grease: flag(tls.grease),
      permuteExtensions: flag(tls.permute_extensions),
      echGrease: flag(tls.ech_grease),
      alps: flag(tls.alps),
      delegatedCredentials: tls.delegated_credentials
        ? String(tls.delegated_credentials)
            .split(":")
            .filter(Boolean).length
        : 0,
      certCompression: tls.cert_compression
        ? String(tls.cert_compression).split(":").filter(Boolean)
        : [],
      padding: tls.padding || "",
      http2: h2 && h2.settings
        ? {
            settings: settings(h2.settings),
            pseudoOrder: h2.pseudo_order || "",
            windowUpdate: h2.window_update ?? null,
            initialWindowSize: h2.initial_window_size ?? null,
          }
        : null,
      http3: record.http3 ? true : false,
      // What this build cannot send from the capture. The lists above are the
      // record's fields, so a deviation is exactly the difference between what
      // the capture held and what the library will put on the wire.
      deviations: (record.deviations || []).slice(0, 3),
    };
  });

const counts = library.reduce(
  (total, record) => {
    const tls = record.tls ?? {};
    total.ciphers += list(tls.ciphers, ":").length;
    total.extensions += list(tls.extension_order, "-").length;
    total.curves += list(tls.curves, ":").length;
    total.sigalgs += list(tls.sigalgs, ":").length;
    return total;
  },
  { ciphers: 0, extensions: 0, curves: 0, sigalgs: 0 },
);

writeFileSync(
  OUT,
  JSON.stringify(
    {
      generatedFrom: "src/fingerprint/builtin.json",
      records: handshakes.length,
      counts,
      handshakes,
    },
    null,
    1,
  ) + "\n",
);

console.log(
  `wrote ${handshakes.length} handshakes to ${OUT} ` +
    `(${counts.ciphers} cipher entries, ${counts.extensions} extension entries)`,
);

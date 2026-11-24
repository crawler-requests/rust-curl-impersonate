// Extracts the live echo comparisons from goal-evidence/echo-latest/*.log:
// each run impersonates a record, calls tls.peet.ws, and tls.peet.ws echoes
// back the ClientHello it received. The site shows the difference between that
// echo and the capture the record came from.
//
// Run after re-running the echo harness:
//
//   node scripts/sync-echo.mjs

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const ECHO_DIR = join(ROOT, "goal-evidence", "echo-latest");
const LIBRARY = JSON.parse(
  readFileSync(join(ROOT, "src", "fingerprint", "builtin.json"), "utf8"),
).fingerprints;
const OUT = join(HERE, "..", "src", "data", "echo.json");

const records = new Map(LIBRARY.map((record) => [record.name, record]));

function captureOf(record) {
  const source = record?.source || "";
  const at = source.indexOf("tools/capture/raw/");
  if (at < 0) return null;
  const file = source.slice(at + "tools/capture/raw/".length).split(/[\s,]+/)[0];
  try {
    return JSON.parse(
      readFileSync(join(ROOT, "tools", "capture", "raw", file), "utf8"),
    );
  } catch {
    return null;
  }
}

const runs = [];
for (const file of readdirSync(ECHO_DIR).filter((name) => name.endsWith(".log"))) {
  const name = file.replace(/\.log$/, "");
  const text = readFileSync(join(ECHO_DIR, file), "utf8");
  const firstLine = text.split("\n", 1)[0];
  const body = text.slice(text.indexOf("\n") + 1);
  let echo;
  try {
    echo = JSON.parse(body);
  } catch {
    continue;
  }
  const record = records.get(name);
  const capture = captureOf(record);
  if (!echo?.tls || !capture?.tls) continue;

  const captureExtensions = (capture.tls.extensions || []).map((ext) => ext.name);
  const echoExtensions = (echo.tls.extensions || []).map((ext) => ext.name);
  const captureJa4 = capture.tls.ja4 || "";
  const missing = captureExtensions.filter((ext) => !echoExtensions.includes(ext));
  const extra = echoExtensions.filter((ext) => !captureExtensions.includes(ext));

  runs.push({
    name,
    status: firstLine.replace(/^status:\s*/, "").trim(),
    httpVersion: echo.http_version || "",
    userAgent: echo.user_agent || "",
    captureJa4,
    echoJa4: echo.tls.ja4 || "",
    captureExtensions: captureExtensions.length,
    echoExtensions: echoExtensions.length,
    // GREASE names carry a random value, so compare the prefix only.
    missing: missing.filter((ext) => !ext.startsWith("TLS_GREASE")).slice(0, 6),
    extra: extra.filter((ext) => !ext.startsWith("TLS_GREASE")).slice(0, 6),
    akamaiCapture: capture.http2?.akamai_fingerprint || capture.http2?.akamai || "",
    akamaiEcho: echo.http2?.akamai_fingerprint || echo.http2?.akamai || "",
  });
}

runs.sort((a, b) => (a.name < b.name ? -1 : 1));
writeFileSync(
  OUT,
  JSON.stringify({ generatedFrom: "goal-evidence/echo-latest", runs }, null, 1) + "\n",
);
console.log(`wrote ${runs.length} echo runs to ${OUT}`);

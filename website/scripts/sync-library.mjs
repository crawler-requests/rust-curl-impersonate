// Copies the crate's fingerprint library into the website's data file.
//
// The website must show exactly what the crate ships, so the records are
// read from src/fingerprint/builtin.json and their JA4 from the capture each
// record names. Run after changing the library:
//
//   npm run sync-library      (or: node scripts/sync-library.mjs)

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const OUT = join(HERE, "..", "src", "data", "records.json");

const library = JSON.parse(
  readFileSync(join(ROOT, "src", "fingerprint", "builtin.json"), "utf8"),
);
const base = library.fingerprints.filter((record) => !record.extends);

function ja4(record) {
  const source = record.source || "";
  const at = source.indexOf("tools/capture/raw/");
  if (at < 0) return "";
  const file = source.slice(at + "tools/capture/raw/".length).split(/[\s,]+/)[0];
  try {
    const capture = JSON.parse(
      readFileSync(join(ROOT, "tools", "capture", "raw", file), "utf8"),
    );
    return capture.tls?.ja4 || "";
  } catch {
    return "";
  }
}

const records = base.map((record) => ({
  name: record.name,
  family: record.family || "",
  client: record.client || "",
  version: record.version || "",
  platform: record.platform || "",
  library: record.library || "",
  fidelity: record.fidelity || "",
  source: record.source || "",
  ja4: ja4(record),
  http1Only: Boolean(record.http1_only),
  deviations: (record.deviations || []).slice(0, 2),
}));

const aliases = library.fingerprints
  .filter((record) => record.extends)
  .map((record) => ({ name: record.name, target: record.extends }));

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(
  OUT,
  JSON.stringify(
    {
      generatedFrom: "src/fingerprint/builtin.json",
      baseRecords: records.length,
      aliases: aliases.length,
      records,
      aliasList: aliases,
    },
    null,
    1,
  ) + "\n",
);
console.log(`wrote ${records.length} records and ${aliases.length} aliases to ${OUT}`);

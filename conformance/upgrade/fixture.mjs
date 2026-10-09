// The 0.1.3 storage fixtures (make-fixture-0.1.3.mjs) for LFCP-02-029:
// copied into a temporary directory before a test opens them, so the
// committed files are never changed. JavaScript with hand-written types
// (fixture.d.mts): sdk-ts has no Node type definitions.

import { cpSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "0.1.3");

/** Copies the SQLite database and its secrets directory into `dir`. */
export function copySqliteFixture(dir) {
  cpSync(join(HERE, "lfcp.sqlite3"), join(dir, "lfcp.sqlite3"));
  cpSync(join(HERE, "secrets"), join(dir, "secrets"), { recursive: true });
  return { db: join(dir, "lfcp.sqlite3"), secrets: join(dir, "secrets") };
}

const dec = (v) =>
  Array.isArray(v)
    ? v.map(dec)
    : v !== null && typeof v === "object"
      ? "$bytes" in v
        ? Uint8Array.from(Buffer.from(v.$bytes, "hex"))
        : "$bigint" in v
          ? BigInt(v.$bigint)
          : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, dec(x)]))
      : v;

/** The IndexedDB dump: version, each store's [key, value] rows, and the secrets. */
export function readIdbFixture() {
  const raw = JSON.parse(readFileSync(join(HERE, "idb.json"), "utf8"));
  return {
    version: raw.version,
    stores: Object.fromEntries(Object.entries(raw.stores).map(([k, rows]) => [k, dec(rows)])),
    secrets: raw.secrets.map(([ref, hex]) => [ref, Uint8Array.from(Buffer.from(hex, "hex"))]),
  };
}

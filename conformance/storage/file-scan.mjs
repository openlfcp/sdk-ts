// Searches every file under a directory for a byte pattern, for the local
// state canary tests (LFCP-02-098). JavaScript with hand-written types
// (file-scan.d.mts), like temp-dir.mjs: sdk-ts has no Node type definitions.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/** The paths, relative to `dir`, of the files under it whose bytes contain `needle`. */
export function filesContaining(dir, needle) {
  const pattern = Buffer.from(needle);
  const out = [];
  const walk = (at, rel) => {
    for (const name of readdirSync(at)) {
      const path = join(at, name);
      const relPath = rel === "" ? name : `${rel}/${name}`;
      if (statSync(path).isDirectory()) walk(path, relPath);
      else if (readFileSync(path).includes(pattern)) out.push(relPath);
    }
  };
  walk(dir, "");
  return out;
}

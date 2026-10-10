#!/usr/bin/env node
// The npm dist-tag of a release version, one rule for release.yml and
// release-check.mjs:
//
//   node scripts/dist-tag.mjs <version>     prints the dist-tag
//
// - a final version (0.2.0) goes to `latest`;
// - a beta (0.2.0-beta.1) goes to `beta`: `latest` stays on the last final
//   version until GA;
// - a release candidate (0.1.0-rc.1) goes to `next`;
// - any other version is refused, so no prerelease reaches a dist-tag by
//   accident.

import { fileURLToPath } from "node:url";

/** The dist-tag of `version`; throws for a version no rule covers. */
export function distTag(version) {
  if (/^\d+\.\d+\.\d+$/.test(version)) return "latest";
  if (/^\d+\.\d+\.\d+-beta\.\d+$/.test(version)) return "beta";
  if (/^\d+\.\d+\.\d+-rc\.\d+$/.test(version)) return "next";
  throw new Error(`no dist-tag for version ${version}: expected X.Y.Z, X.Y.Z-beta.N or X.Y.Z-rc.N`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const version = process.argv[2];
  if (!version) {
    console.error("usage: dist-tag.mjs <version>");
    process.exit(2);
  }
  try {
    console.log(distTag(version));
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}

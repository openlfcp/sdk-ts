#!/usr/bin/env node
// After a publish (release.yml): the eight @openlfcp/* packages at VERSION,
// as the registry serves them to anyone.
//
//   node scripts/registry-check.mjs <version> <dist-tag> [--wait-ms N]
//
// 1. Each package's registry metadata: the version exists, its tarball holds
//    more than package.json, README.md and LICENSE (dist.fileCount > 3: sdk-ts
//    0.1.2 went out without dist/), and the dist-tag names it.
// 2. A fresh project installs all eight from the registry and imports them.
//
// A version just published may not be installable for a while (npm shows it
// as validating): both steps are retried until --wait-ms (default 10 min).

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PUBLISH_ORDER } from "./packages.mjs";

const [version, tag] = process.argv.slice(2);
if (!version || !tag) {
  console.error("usage: registry-check.mjs <version> <dist-tag> [--wait-ms N]");
  process.exit(2);
}
const waitArg = process.argv.indexOf("--wait-ms");
const waitMs = waitArg > 0 ? Number(process.argv[waitArg + 1]) : 600_000;
const deadline = Date.now() + waitMs;
const npm = (args, cwd) =>
  execFileSync("npm", args, { cwd, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Problems with the registry metadata of every package; empty when all is right. */
function metadataProblems() {
  const problems = [];
  for (const name of PUBLISH_ORDER) {
    const pkg = `@openlfcp/${name}`;
    try {
      const info = JSON.parse(npm(["view", `${pkg}@${version}`, "--json"]));
      if (info.version !== version) problems.push(`${pkg}: version ${info.version}`);
      const files = info.dist?.fileCount;
      if (!(files > 3)) problems.push(`${pkg}@${version}: dist.fileCount ${files} (no dist/?)`);
      if (info["dist-tags"]?.[tag] !== version)
        problems.push(`${pkg}: ${tag} is ${info["dist-tags"]?.[tag]}, not ${version}`);
    } catch (e) {
      problems.push(`${pkg}@${version}: ${String(e.stderr ?? e.message).split("\n")[0]}`);
    }
  }
  return problems;
}

function installProblems() {
  const app = mkdtempSync(join(tmpdir(), "openlfcp-registry-check-"));
  try {
    writeFileSync(
      join(app, "package.json"),
      JSON.stringify({ name: "registry-check", private: true, type: "module" }),
    );
    npm(
      [
        "install",
        "--no-audit",
        "--no-fund",
        "--prefer-online",
        ...PUBLISH_ORDER.map((n) => `@openlfcp/${n}@${version}`),
      ],
      app,
    );
    const imports = PUBLISH_ORDER.map((n) => `await import("@openlfcp/${n}");`).join(" ");
    execFileSync(
      "node",
      ["--input-type=module", "-e", `${imports} console.log("all eight import")`],
      {
        cwd: app,
        stdio: ["ignore", "inherit", "pipe"],
      },
    );
    return [];
  } catch (e) {
    return [
      `install or import: ${String(e.stderr ?? e.message)
        .split("\n")
        .slice(0, 5)
        .join(" | ")}`,
    ];
  } finally {
    rmSync(app, { recursive: true, force: true });
  }
}

let problems = [];
for (let attempt = 1; ; attempt++) {
  problems = metadataProblems();
  if (problems.length === 0) problems = installProblems();
  if (problems.length === 0) break;
  if (Date.now() >= deadline) break;
  console.log(`attempt ${attempt}: not yet (${problems[0]}); retrying in 30 s`);
  await sleep(30_000);
}
for (const p of problems) console.log(`FAIL ${p}`);
console.log(
  problems.length === 0 ? `registry check PASSED: ${version} on ${tag}` : "registry check FAILED",
);
process.exit(problems.length === 0 ? 0 : 1);

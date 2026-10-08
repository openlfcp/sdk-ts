#!/usr/bin/env node
// Release check for the @openlfcp/* npm packages (local, offline-capable):
//
//   pnpm release:check [--keep]
//
// 1. A clean build in a fresh copy of this checkout (tracked and new,
//    non-ignored files of the working tree), so no stale dist file can
//    reach a tarball.
// 2. `pnpm pack` of every package into a temporary directory.
// 3. Each tarball may contain only package/package.json, README.md, LICENSE
//    and dist/** (no tests, src, source maps, .env, keys or fixtures).
// 4. Each packed package.json: the release version, every @openlfcp/*
//    dependency rewritten from workspace:^ to ^<version> (or the exact
//    version), no "workspace:" left, publishConfig { access public, tag
//    "latest" for a final version, "next" for a prerelease }, license,
//    repository and engines set.
// 5. The eight tarballs installed into a fresh project with npm (from the
//    tarball files; --prefer-offline uses the npm cache for third-party
//    dependencies), then every package imported in Node ESM, with a small
//    round trip: a Principal from fresh keys, a wire message encoded and
//    decoded, a Shared Objects Task, in-memory and SQLite storage.
// 6. A summary with each tarball's size and file count.
// 7. This checkout as `pnpm publish` would pack it (`npm pack --dry-run`):
//    the same files as the clean build's tarball, dist/ included. A
//    publish uploads the checkout, not the clean copy: build it first.
//
// Nothing is published. Exit status 0 only when every check passed. The
// temporary directory is removed unless --keep is given.

import { execFileSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkoutPackProblems, packJsonFiles } from "./pack-files.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const keep = process.argv.includes("--keep");

import { PUBLISH_ORDER } from "./packages.mjs";

export { PUBLISH_ORDER };

/** Every package is released at @openlfcp/core's version. */
const VERSION = JSON.parse(
  readFileSync(join(root, "packages", "core", "package.json"), "utf8"),
).version;
/** The dist-tag: `next` for a prerelease (`0.1.0-rc.1`), `latest` for a final release. */
const DIST_TAG = VERSION.includes("-") ? "next" : "latest";
const failures = [];
const fail = (what) => {
  failures.push(what);
  console.log(`  FAIL ${what}`);
};
const run = (cmd, args, cwd, quiet = true) =>
  execFileSync(cmd, args, {
    cwd,
    stdio: quiet ? ["ignore", "pipe", "pipe"] : "inherit",
    encoding: "utf8",
  });
const step = (title) => console.log(`\n== ${title}`);

/** The smoke test run inside the fresh project (Node ESM, installed tarballs only). */
const SMOKE = `
import * as core from "@openlfcp/core";
import { generateAgreementKeyPair, generateSigningKeyPair, sha256 } from "@openlfcp/crypto";
import { InMemoryLfcpStorage } from "@openlfcp/storage";
import * as contract from "@openlfcp/storage/contract";
import {
  createMessage, decodeMessage, decodePrincipalDescriptor, encodeMessage,
  encodePrincipalDescriptor, principalDescriptorFromKeys,
} from "@openlfcp/wire";
import { encode } from "@openlfcp/wire/cbor";
import { SqliteLfcpStorage } from "@openlfcp/storage-node";
import { IdbLfcpStorage } from "@openlfcp/storage-idb";
import { createTask, initializeAutomerge, SharedObjectsReplica } from "@openlfcp/shared-objects";
import { admitBatch, deriveDomainActorId } from "@openlfcp/shared-objects/admission";
import { profileModel, SECTIONS_PROFILE_ID } from "@openlfcp/shared-objects/sections";
import { SyncClient, OutboundQueue } from "@openlfcp/client";

const ok = (cond, what) => { if (!cond) throw new Error("smoke: " + what); console.log("ok " + what); };

// A Principal from fresh keys, its descriptor through the wire codec.
const descriptor = principalDescriptorFromKeys(generateSigningKeyPair(), generateAgreementKeyPair());
const again = decodePrincipalDescriptor(encodePrincipalDescriptor(descriptor));
ok(core.toHex(again.principalId) === core.toHex(descriptor.principalId), "Principal descriptor round trip");
// A wire message encoded and decoded.
const ping = createMessage("PING", { payload: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8) });
const back = decodeMessage(encodeMessage(ping));
ok(back.type === "PING" && core.toHex(back.messageId) === core.toHex(ping.messageId), "PING message round trip");
ok(encode(1n).length === 1 && sha256(new Uint8Array()).length === 32, "deterministic CBOR and SHA-256");
// Storage: in memory and SQLite.
const memory = new InMemoryLfcpStorage();
ok((await memory.commit([{ op: "put-local-mark", key: "k", value: "v" }])).ok && (await memory.localMarks.get("k")) === "v", "in-memory storage");
const sqlite = SqliteLfcpStorage.open(":memory:");
ok((await sqlite.resources.list()).length === 0, "SQLite storage (better-sqlite3)");
sqlite.close();
ok(typeof IdbLfcpStorage.open === "function" && typeof contract === "object", "storage-idb and the storage contract load");
// Shared Objects: a Task through Automerge.
await initializeAutomerge();
const R = core.generateResourceId();
const { replica } = SharedObjectsReplica.create({ resource: R, principal: descriptor.principalId });
const task = createTask({ title: "Release check", createdBy: descriptor.principalId });
replica.apply(task.intent);
ok(replica.task(task.task.id)?.task?.title === "Release check", "Shared Objects Task through Automerge");
ok(typeof SyncClient === "function" && typeof OutboundQueue === "function", "client loads");
ok(typeof admitBatch === "function" && deriveDomainActorId("D", R, descriptor.principalId).length === 32, "the shared admission module loads (@openlfcp/shared-objects/admission)");
ok(profileModel(SECTIONS_PROFILE_ID).kind === "shared-sections", "the section profile loads (@openlfcp/shared-objects/sections)");
`;

const work = mkdtempSync(join(tmpdir(), "openlfcp-release-check-"));
try {
  // ---------------------------------------------------------------- 1. copy, build
  step("clean build in a fresh copy");
  const copy = join(work, "sdk-ts");
  const files = run("git", ["ls-files", "-co", "--exclude-standard", "-z"], root)
    .split("\0")
    .filter((f) => f !== "");
  for (const f of files) {
    let st;
    try {
      st = statSync(join(root, f));
    } catch {
      continue; // deleted in the working tree
    }
    if (!st.isFile()) continue;
    mkdirSync(dirname(join(copy, f)), { recursive: true });
    cpSync(join(root, f), join(copy, f));
  }
  run("pnpm", ["install", "--frozen-lockfile", "--prefer-offline"], copy);
  run("pnpm", ["build"], copy);
  console.log(`  copied ${files.length} files, installed, built`);

  // ---------------------------------------------------------------- 2. pack
  step("pack");
  const packs = join(work, "packs");
  mkdirSync(packs);
  const manifests = new Map();
  for (const name of PUBLISH_ORDER) {
    const dir = join(copy, "packages", name);
    manifests.set(name, JSON.parse(readFileSync(join(dir, "package.json"), "utf8")));
    run("pnpm", ["pack", "--pack-destination", packs], dir);
  }
  const tarballs = new Map();
  /** Each clean tarball's file paths, without the package/ prefix (step 7). */
  const cleanFiles = new Map();
  for (const name of PUBLISH_ORDER) {
    const file = join(packs, `openlfcp-${name}-${manifests.get(name).version}.tgz`);
    try {
      statSync(file);
      tarballs.set(name, file);
    } catch {
      // reported below
    }
  }
  for (const name of PUBLISH_ORDER)
    if (!tarballs.has(name)) fail(`no tarball for @openlfcp/${name}`);

  // ---------------------------------------------------------------- 3. contents
  step("tarball contents");
  const ALLOWED = /^package\/(package\.json|README\.md|LICENSE|dist\/.+\.(js|d\.ts))$/;
  const summary = [];
  for (const [name, tarball] of tarballs) {
    const entries = run("tar", ["-tzf", tarball], work)
      .split("\n")
      .filter((l) => l !== "");
    const bad = entries.filter((e) => !ALLOWED.test(e));
    for (const e of bad) fail(`@openlfcp/${name}: ${e} must not be published`);
    for (const required of [
      "package/package.json",
      "package/README.md",
      "package/LICENSE",
      "package/dist/index.js",
      "package/dist/index.d.ts",
    ])
      if (!entries.includes(required)) fail(`@openlfcp/${name}: ${required} is missing`);
    summary.push({ name, bytes: statSync(tarball).size, files: entries.length });
    cleanFiles.set(
      name,
      entries.map((e) => e.replace(/^package\//, "")),
    );
  }
  if (failures.length === 0)
    console.log("  only package.json, README.md, LICENSE and dist/**/*.{js,d.ts}");

  // ---------------------------------------------------------------- 4. manifests
  step("packed package.json");
  for (const [name, tarball] of tarballs) {
    const m = JSON.parse(run("tar", ["-xzOf", tarball, "package/package.json"], work));
    const version = manifests.get(name).version;
    const where = `@openlfcp/${name}`;
    if (m.name !== where) fail(`${where}: name is ${m.name}`);
    if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(m.version))
      fail(`${where}: version ${m.version}`);
    if (m.version !== VERSION)
      fail(`${where}: version ${m.version}, @openlfcp/core has ${VERSION}`);
    if (JSON.stringify(m).includes("workspace:")) fail(`${where}: a workspace: range is left`);
    for (const [dep, range] of Object.entries({ ...m.dependencies, ...m.peerDependencies }))
      if (dep.startsWith("@openlfcp/") && range !== `^${version}` && range !== version)
        fail(`${where}: ${dep} is "${range}", expected "^${version}"`);
    if (m.publishConfig?.access !== "public") fail(`${where}: publishConfig.access is not public`);
    if (m.publishConfig?.tag !== DIST_TAG)
      fail(`${where}: publishConfig.tag is not "${DIST_TAG}" (version ${m.version})`);
    if (m.license !== "Apache-2.0") fail(`${where}: license ${m.license}`);
    if (m.repository?.directory !== `packages/${name}`) fail(`${where}: repository.directory`);
    if (m.engines?.node === undefined) fail(`${where}: engines.node is missing`);
    if (m.type !== "module" || m.exports?.["."]?.import === undefined)
      fail(`${where}: not an ESM package with exports`);
    const deps = Object.keys(m.dependencies ?? {}).filter((d) => d.startsWith("@openlfcp/"));
    const later = deps.filter(
      (d) => PUBLISH_ORDER.indexOf(d.slice(10)) > PUBLISH_ORDER.indexOf(name),
    );
    for (const d of later) fail(`${where} depends on ${d}, which is published after it`);
    console.log(
      `  ${where}@${m.version}: ${deps.map((d) => `${d}@${m.dependencies[d]}`).join(", ") || "no @openlfcp dependency"}`,
    );
  }

  // ---------------------------------------------------------------- 5. install, smoke
  step("install the tarballs into a fresh project and import them");
  const app = join(work, "app");
  mkdirSync(app);
  writeFileSync(
    join(app, "package.json"),
    JSON.stringify({ name: "release-check-app", private: true, type: "module" }),
  );
  run(
    "npm",
    [
      "install",
      "--prefer-offline",
      "--no-audit",
      "--no-fund",
      "--loglevel=error",
      ...PUBLISH_ORDER.map((n) => tarballs.get(n)).filter(Boolean),
    ],
    app,
  );
  writeFileSync(join(app, "smoke.mjs"), SMOKE);
  try {
    console.log(run("node", ["smoke.mjs"], app).trimEnd().replace(/^/gm, "  "));
  } catch (e) {
    fail(`the smoke test failed:\n${e.stdout ?? ""}${e.stderr ?? e.message}`);
  }

  // ---------------------------------------------------------------- 6. summary
  step("summary");
  for (const s of summary)
    console.log(
      `  @openlfcp/${s.name.padEnd(15)} ${(s.bytes / 1024).toFixed(1).padStart(8)} KiB  ${String(s.files).padStart(4)} files`,
    );
  const total = summary.reduce((a, s) => a + s.bytes, 0);
  console.log(
    `  total ${(total / 1024).toFixed(1)} KiB; publish order: ${PUBLISH_ORDER.join(" → ")}`,
  );
  console.log(`  version ${VERSION}, dist-tag ${DIST_TAG}`);

  // ---------------------------------------------------------------- 7. this checkout
  step("this checkout as pnpm publish packs it");
  let packed = 0;
  for (const name of PUBLISH_ORDER) {
    const files = packJsonFiles(
      run("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], join(root, "packages", name)),
    );
    const problems = checkoutPackProblems(name, files, cleanFiles.get(name) ?? []);
    for (const p of problems) fail(p);
    if (problems.length === 0) packed++;
  }
  if (packed === PUBLISH_ORDER.length)
    console.log("  every package as built in the clean copy, dist/ included");
  else console.log("  run `pnpm build` in this checkout before publishing from it");
} catch (e) {
  fail(e.stderr ? `${e.message}\n${e.stderr}` : String(e.message ?? e));
} finally {
  if (keep) console.log(`\n(kept ${work})`);
  else rmSync(work, { recursive: true, force: true });
}

console.log(
  failures.length === 0 ? "\nrelease check PASSED" : `\nrelease check FAILED (${failures.length})`,
);
process.exit(failures.length === 0 ? 0 : 1);

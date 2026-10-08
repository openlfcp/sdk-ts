#!/usr/bin/env node
// What `pnpm publish` would upload from this checkout, compared with the
// tarball of a clean build (release-check.mjs, step 7). A publish packs the
// checkout's own files: without `pnpm build` it has no dist/, and npm takes
// the package anyway (sdk-ts 0.1.2 went out that way).
//
//   node scripts/pack-files.mjs --self-test
//
// checkoutPackProblems is pure, so the self-test needs no npm and no build.

/** Files a package must publish, whatever else it has. */
export const REQUIRED = [
  "package.json",
  "README.md",
  "LICENSE",
  "dist/index.js",
  "dist/index.d.ts",
];

/**
 * Problems of one package's checkout pack (`npm pack --dry-run --json`
 * file paths) against the clean build's tarball (paths without the
 * `package/` prefix). Empty when they hold the same files.
 */
export function checkoutPackProblems(name, checkout, clean) {
  const have = new Set(checkout);
  const want = new Set(clean);
  const problems = [];
  for (const f of REQUIRED)
    if (!have.has(f)) problems.push(`@openlfcp/${name}: the checkout would publish no ${f}`);
  const missing = [...want].filter((f) => !have.has(f) && !REQUIRED.includes(f));
  const extra = [...have].filter((f) => !want.has(f));
  if (missing.length > 0)
    problems.push(
      `@openlfcp/${name}: the checkout lacks ${missing.length} file(s) of the clean build (${missing.slice(0, 3).join(", ")}${missing.length > 3 ? ", …" : ""})`,
    );
  if (extra.length > 0)
    problems.push(
      `@openlfcp/${name}: the checkout would publish ${extra.length} file(s) the clean build has not (${extra.slice(0, 3).join(", ")}${extra.length > 3 ? ", …" : ""}): a stale dist/`,
    );
  return problems;
}

/** The file paths of `npm pack --dry-run --json` output (one package). */
export function packJsonFiles(json) {
  const parsed = JSON.parse(json);
  const entry = Array.isArray(parsed) ? parsed[0] : parsed;
  return (entry?.files ?? []).map((f) => f.path);
}

function selfTest() {
  const clean = [...REQUIRED, "dist/ids.js", "dist/ids.d.ts"];
  const cases = [
    ["a built checkout", clean, 0],
    ["the 0.1.2 incident: no dist/", ["package.json", "README.md", "LICENSE"], 3],
    ["a partial dist/", [...REQUIRED], 1],
    ["a stale extra file", [...clean, "dist/old.js"], 1],
  ];
  let failed = 0;
  for (const [what, checkout, expected] of cases) {
    const got = checkoutPackProblems("core", checkout, clean);
    const pass = expected === 0 ? got.length === 0 : got.length >= 1;
    if (!pass) failed++;
    console.log(`${pass ? "ok  " : "FAIL"}  ${what} (${got.length} problem(s))`);
  }
  const files = packJsonFiles(
    JSON.stringify([{ files: [{ path: "package.json" }, { path: "dist/index.js" }] }]),
  );
  const parsedOk = files.join(",") === "package.json,dist/index.js";
  if (!parsedOk) failed++;
  console.log(`${parsedOk ? "ok  " : "FAIL"}  npm pack --json file list`);
  process.exit(failed === 0 ? 0 : 1);
}

if (process.argv.includes("--self-test")) selfTest();

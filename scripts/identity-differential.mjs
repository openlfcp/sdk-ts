#!/usr/bin/env node
// Differential run of the identity corpora (LFCP-04-412, IDENTITY-PROFILE-01
// §12): compares two lfcp-identity-outcomes/1 exports, sdk-ts's and
// sdk-rs's, case by case and flow step by step. Neither SDK reads the
// other's code; only their exported outcomes meet here.
//
//   node scripts/identity-differential.mjs --ts <dir> --rs <dir> [--out <file.md>]
//   node scripts/identity-differential.mjs --self-test
//
// Each directory holds identity-wire.json, identity-profile.json and
// identity-flows.json. sdk-ts writes them with LFCP_IDENTITY_REPORT_DIR set
// (conformance/identity/*.test.ts), sdk-rs with the same variable
// (docs/identity-conformance.md there).
//
// What is compared, for a case and for each flow step:
// - `outcome`: "accept", a wire code, a profile code or a local outcome;
// - `diagnostic` (when both give one) and `disposition`;
// - `accepted_ids`, in order;
// - `post_state` and every other field both sides give, recursively: a
//   value both sides give must be equal; a field only one side gives is
//   recorded as one-sided, never as a divergence (each SDK reports the
//   state it derives, and they need not derive the same facts).
// An "N/A" on either side is not compared; its reason is listed.
//
// Every divergence must be explained in
// conformance/identity/differential-known.json, which records, for each,
// the side the specification text supports. The exit code is 0 only when
// the spec pins agree, every divergence is explained, and no explanation is
// stale.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const FILES = ["identity-wire.json", "identity-profile.json", "identity-flows.json"];
const FORMAT = "lfcp-identity-outcomes/1";
/** Fields that describe the report, not the outcome. */
const NOT_COMPARED = new Set(["n", "detail", "not_applicable", "reason", "simulation"]);
/**
 * Lists the corpora define as sets (changes admitted, pending or held by a
 * replica; units excluded; Principals registered or suspended): compared
 * without their order, which is delivery or implementation order.
 */
const SET_FIELDS = new Set(["admitted", "pending", "held", "excluded", "registered", "suspended"]);

const isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const stable = (v) =>
  JSON.stringify(v, (_k, x) =>
    isObject(x)
      ? Object.fromEntries(
          Object.keys(x)
            .sort()
            .map((k) => [k, x[k]]),
        )
      : x,
  );

/**
 * Compares two reported values. Pushes conflicting paths to `diffs` and
 * paths given by one side only to `oneSided` (as `<path> (<side>)`).
 */
export function compareValues(ts, rs, path, diffs, oneSided) {
  if (ts === undefined || rs === undefined) {
    if (ts !== undefined) oneSided.push(`${path} (sdk-ts)`);
    if (rs !== undefined) oneSided.push(`${path} (sdk-rs)`);
    return;
  }
  // A null post-state is "nothing reported", as an absent one.
  if ((ts === null) !== (rs === null) && path.endsWith("post_state")) {
    oneSided.push(`${path} (${ts === null ? "sdk-rs" : "sdk-ts"})`);
    return;
  }
  if (isObject(ts) && isObject(rs)) {
    for (const k of [...new Set([...Object.keys(ts), ...Object.keys(rs)])].sort())
      compareValues(ts[k], rs[k], `${path}.${k}`, diffs, oneSided);
    return;
  }
  // A frontier entry without extra ranges is its contiguous count (W §28.1): n = {contiguous: n, extra_ranges: []}.
  const frontier = (v) =>
    /\.frontier\.[^.]+$/.test(path) && typeof v === "number"
      ? { contiguous: v, extra_ranges: [] }
      : v;
  ts = frontier(ts);
  rs = frontier(rs);
  const field = path.slice(path.lastIndexOf(".") + 1);
  const asSet = (v) => (SET_FIELDS.has(field) && Array.isArray(v) ? [...v].map(stable).sort() : v);
  if (stable(asSet(ts)) !== stable(asSet(rs))) diffs.push({ path, ts, rs });
}

/** One outcome (a case, or a flow step) against the other side's. */
function compareOutcome(ts, rs, path, out) {
  const na = (r) => r?.outcome === "N/A";
  if (ts === undefined || rs === undefined) {
    out.missing.push({ path, side: ts === undefined ? "sdk-ts" : "sdk-rs" });
    return;
  }
  const flow = Array.isArray(ts.steps) || Array.isArray(rs.steps);
  if (na(ts) || na(rs)) {
    const reasons = (r) =>
      Array.isArray(r.not_applicable)
        ? r.not_applicable
            .map(
              (x) =>
                `${x.step === undefined ? "" : `step ${x.step}`}${x.field === undefined ? "" : ` ${x.field}`}: ${x.reason}`,
            )
            .join("; ")
        : (r.not_applicable ?? r.reason);
    out.na.push({
      path,
      side: na(ts) && na(rs) ? "both" : na(ts) ? "sdk-ts" : "sdk-rs",
      reason: [na(ts) ? `sdk-ts: ${reasons(ts)}` : "", na(rs) ? `sdk-rs: ${reasons(rs)}` : ""]
        .filter(Boolean)
        .join(" / "),
      other: na(ts) && na(rs) ? "" : na(ts) ? rs.outcome : ts.outcome,
    });
    // A flow is N/A in part: its steps are still compared one by one.
    if (!flow) return;
  }
  const diffs = [];
  const oneSided = [];
  for (const k of [...new Set([...Object.keys(ts), ...Object.keys(rs)])].sort()) {
    if (NOT_COMPARED.has(k) || k === "steps") continue;
    if (k === "outcome" && (na(ts) || na(rs))) continue;
    if (k === "diagnostic" && (ts[k] === undefined || rs[k] === undefined)) continue;
    compareValues(ts[k], rs[k], `${path}.${k}`, diffs, oneSided);
  }
  out.oneSided.push(...oneSided);
  for (const d of diffs) out.diffs.push(d);
  if (Array.isArray(ts.steps) || Array.isArray(rs.steps)) {
    const byN = (steps) => new Map((steps ?? []).map((s) => [s.n, s]));
    const a = byN(ts.steps);
    const b = byN(rs.steps);
    for (const n of [...new Set([...a.keys(), ...b.keys()])].sort((x, y) => x - y))
      compareOutcome(a.get(n), b.get(n), `${path}#${n}`, out);
  }
  if (diffs.length === 0) out.matched.push(path);
}

/** Compares one export file of both sides. */
export function compareExports(name, ts, rs) {
  const out = { name, problems: [], matched: [], na: [], diffs: [], oneSided: [], missing: [] };
  for (const [side, x] of [
    ["sdk-ts", ts],
    ["sdk-rs", rs],
  ])
    if (x.format !== FORMAT) out.problems.push(`${side} ${name} is ${x.format}, not ${FORMAT}`);
  if (stable(ts.spec) !== stable(rs.spec))
    out.problems.push(`${name}: the spec pins differ: ${stable(ts.spec)} vs ${stable(rs.spec)}`);
  const ids = [...new Set([...Object.keys(ts.cases), ...Object.keys(rs.cases)])].sort();
  for (const id of ids) compareOutcome(ts.cases[id], rs.cases[id], id, out);
  out.cases = ids.length;
  const caseOf = (path) => path.split(/[.#]/)[0];
  const divergent = new Set(out.diffs.map((d) => caseOf(d.path)));
  // A flow is compared step by step even when one side calls it N/A in part.
  const isFlow = (id) => Array.isArray(ts.cases[id]?.steps) && Array.isArray(rs.cases[id]?.steps);
  const naCases = new Set(
    out.na.filter((n) => !n.path.includes("#") && !isFlow(n.path)).map((n) => n.path),
  );
  const naSteps = new Set(
    out.na.filter((n) => n.path.includes("#") || isFlow(n.path)).map((n) => caseOf(n.path)),
  );
  out.counts = {
    divergent: divergent.size,
    na: naCases.size,
    withNaSteps: [...naSteps].filter((id) => !divergent.has(id) && !naCases.has(id)).length,
    match: ids.filter((id) => !divergent.has(id) && !naCases.has(id) && !naSteps.has(id)).length,
  };
  return out;
}

const keyOf = (corpus, path) => `${corpus}:${path}`;

/** Matches divergences against the known list; returns unexplained ones and stale entries. */
export function explain(results, known) {
  const entries = new Map(known.map((k) => [keyOf(k.corpus, k.path), k]));
  const used = new Set();
  const unexplained = [];
  for (const r of results)
    for (const d of r.diffs) {
      const k = keyOf(r.name, d.path);
      if (entries.has(k)) used.add(k);
      else unexplained.push({ corpus: r.name, ...d });
    }
  const stale = known.filter((k) => !used.has(keyOf(k.corpus, k.path)));
  return { unexplained, stale };
}

function summarizeOneSided(paths) {
  // Paths without case IDs: ".post_state.devices.DEV_A.leaf (sdk-rs)" counted by shape.
  const counts = new Map();
  for (const p of paths) {
    const shape = p
      .replace(/^[^.#]+(#\d+)?/, "")
      .replace(/\.(devices|roles|queries|revoked|tables|candidates)\.[^.]+/g, ".$1.<label>");
    counts.set(shape, (counts.get(shape) ?? 0) + 1);
  }
  return [...counts.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
}

const short = (v) => {
  const s = stable(v);
  return s.length > 120 ? `${s.slice(0, 117)}...` : s;
};

export function markdown(results, known, { unexplained, stale }) {
  const lines = ["# Identity differential: sdk-ts vs sdk-rs", ""];
  lines.push(
    "| Corpus | Cases | Match | Match, some steps N/A | Case N/A | Divergent | N/A entries | One-sided fields |",
  );
  lines.push("|---|---|---|---|---|---|---|---|");
  for (const r of results) {
    const c = r.counts;
    lines.push(
      `| ${r.name} | ${r.cases} | ${c.match} | ${c.withNaSteps} | ${c.na} | ${c.divergent} | ${r.na.length} | ${r.oneSided.length} |`,
    );
  }
  lines.push("");
  for (const r of results) {
    if (r.problems.length > 0) lines.push(`Problems in ${r.name}: ${r.problems.join("; ")}`, "");
    if (r.missing.length > 0)
      lines.push(
        `Missing in ${r.name}: ${r.missing.map((m) => `${m.path} (no ${m.side} outcome)`).join(", ")}`,
        "",
      );
  }
  lines.push("## Divergences", "");
  const all = results.flatMap((r) => r.diffs.map((d) => ({ corpus: r.name, ...d })));
  if (all.length === 0) lines.push("None.", "");
  else {
    lines.push("| Corpus | Path | sdk-ts | sdk-rs | Right by the text | Why |");
    lines.push("|---|---|---|---|---|---|");
    const byKey = new Map(known.map((k) => [keyOf(k.corpus, k.path), k]));
    for (const d of all) {
      const k = byKey.get(keyOf(d.corpus, d.path));
      lines.push(
        `| ${d.corpus} | \`${d.path}\` | \`${short(d.ts)}\` | \`${short(d.rs)}\` | ${k?.right ?? "**unexplained**"} | ${k?.why ?? ""} |`,
      );
    }
    lines.push("");
  }
  lines.push("## N/A", "");
  const na = results.flatMap((r) => r.na.map((n) => ({ corpus: r.name, ...n })));
  if (na.length === 0) lines.push("None.", "");
  else {
    lines.push("| Corpus | Case / step | N/A on | Other side | Reason |");
    lines.push("|---|---|---|---|---|");
    for (const n of na)
      lines.push(
        `| ${n.corpus} | \`${n.path}\` | ${n.side} | ${n.other ?? ""} | ${String(n.reason ?? "").replaceAll("|", "\\|")} |`,
      );
    lines.push("");
  }
  lines.push("## One-sided fields (reported by one SDK only; not compared)", "");
  for (const r of results) {
    const s = summarizeOneSided(r.oneSided);
    if (s.length === 0) continue;
    lines.push(`${r.name}:`, "");
    for (const [shape, n] of s) lines.push(`- \`${shape || "(case)"}\`: ${n}`);
    lines.push("");
  }
  if (unexplained.length > 0 || stale.length > 0) {
    lines.push("## Problems", "");
    for (const u of unexplained) lines.push(`- unexplained: ${u.corpus} \`${u.path}\``);
    for (const s of stale) lines.push(`- stale explanation: ${s.corpus} \`${s.path}\``);
    lines.push("");
  }
  return lines.join("\n");
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i < 0 ? undefined : process.argv[i + 1];
}

function main() {
  const tsDir = arg("--ts");
  const rsDir = arg("--rs");
  if (tsDir === undefined || rsDir === undefined) {
    process.stderr.write("usage: identity-differential.mjs --ts <dir> --rs <dir> [--out <file>]\n");
    process.exit(2);
  }
  const read = (dir, f) => JSON.parse(readFileSync(join(resolve(dir), f), "utf8"));
  const results = FILES.map((f) => compareExports(f, read(tsDir, f), read(rsDir, f)));
  const known = JSON.parse(
    readFileSync(join(ROOT, "conformance/identity/differential-known.json"), "utf8"),
  ).divergences;
  const verdict = explain(results, known);
  const text = markdown(results, known, verdict);
  const out = arg("--out");
  if (out !== undefined) writeFileSync(out, `${text}\n`);
  process.stdout.write(`${text}\n`);
  const problems = results.flatMap((r) => [...r.problems, ...r.missing.map((m) => m.path)]);
  process.exit(problems.length + verdict.unexplained.length + verdict.stale.length === 0 ? 0 : 1);
}

function selfTest() {
  const spec = { repository: "r", tag: "t", commit: "c" };
  const mk = (cases) => ({ format: FORMAT, implementation: "x", spec, cases });
  const r = compareExports(
    "identity-wire.json",
    mk({
      a: { outcome: "accept", accepted_ids: ["01"], post_state: { x: 1, only_ts: 2 } },
      b: { outcome: "AUTHORIZATION_FAILED", accepted_ids: [], post_state: null },
      c: { outcome: "N/A", not_applicable: "why" },
      f: { outcome: "accept", steps: [{ n: 1, outcome: "accept", phase: "pending" }] },
    }),
    mk({
      a: { outcome: "accept", accepted_ids: ["01"], post_state: { x: 1, only_rs: 3 } },
      b: { outcome: "MALFORMED_MESSAGE", accepted_ids: [], post_state: null },
      c: { outcome: "accept", accepted_ids: [] },
      f: { outcome: "accept", steps: [{ n: 1, outcome: "accept", phase: "complete" }] },
    }),
  );
  const fail = (m) => {
    process.stderr.write(`identity-differential self-test: ${m}\n`);
    process.exit(1);
  };
  if (r.problems.length !== 0) fail(`problems ${r.problems}`);
  if (r.diffs.map((d) => d.path).join() !== "b.outcome,f#1.phase") fail(`diffs ${stable(r.diffs)}`);
  if (r.oneSided.join() !== "a.post_state.only_rs (sdk-rs),a.post_state.only_ts (sdk-ts)")
    fail(`one-sided ${stable(r.oneSided)}`);
  if (r.na.length !== 1 || r.na[0].side !== "sdk-ts") fail(`na ${stable(r.na)}`);
  const v = explain(
    [r],
    [
      { corpus: "identity-wire.json", path: "b.outcome", right: "sdk-ts", why: "§1" },
      { corpus: "identity-wire.json", path: "gone.outcome", right: "sdk-ts", why: "§2" },
    ],
  );
  if (v.unexplained.map((u) => u.path).join() !== "f#1.phase") fail(`unexplained ${stable(v)}`);
  if (v.stale.map((s) => s.path).join() !== "gone.outcome") fail(`stale ${stable(v.stale)}`);
  const pins = compareExports("x", mk({}), { ...mk({}), spec: { ...spec, commit: "d" } });
  if (pins.problems.length !== 1) fail("differing spec pins are not a problem");
  process.stdout.write("identity-differential self-test: ok\n");
}

if (process.argv.includes("--self-test")) selfTest();
else if (process.argv[1] === fileURLToPath(import.meta.url)) main();

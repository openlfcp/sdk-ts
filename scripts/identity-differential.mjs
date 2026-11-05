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
// - the required fields: a case's `outcome`, `accepted_ids` and
//   `post_state` (null allowed), a flow's `post_state` and `steps`, a step's
//   `outcome`. A required field one side lacks is a divergence;
// - every other field either side gives, recursively, by membership: a key
//   of a state table (devices, roles, revoked, …) or of any other object
//   that one side gives and the other does not is a divergence, unless it
//   is a documented schema difference of
//   conformance/identity/differential-schema.json (each entry names the
//   corpus, case, step and field it covers, the side that gives the field
//   and why; an entry that covers nothing is stale), or a field the other
//   side declares not applicable for that step;
// - values both sides give must be equal. Lists the corpora define as sets
//   are compared without order, and a frontier entry n equals
//   {contiguous: n, extra_ranges: []} (W §28.1; the fixtures use both).
// A case or step that either side reports as "N/A" (not applicable by the
// text) or "not verified" (applicable, but not run by that side's harness)
// is not compared; both are listed with their reasons. A flow's top-level
// `outcome` summarises its steps, which are compared one by one.
//
// Every divergence must be explained in
// conformance/identity/differential-known.json, which records, for each,
// the side the specification text supports. The exit code is 0 only when
// the spec pins agree, every divergence is explained, and no explanation or
// schema entry is stale.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const FILES = ["identity-wire.json", "identity-profile.json", "identity-flows.json"];
const FORMAT = "lfcp-identity-outcomes/1";
/** Fields that describe the report, not the outcome. */
const NOT_COMPARED = new Set([
  "n",
  "detail",
  "not_applicable",
  "not_verified",
  "reason",
  "simulation",
]);
const REQUIRED_CASE = ["outcome", "accepted_ids", "post_state"];
const REQUIRED_FLOW = ["post_state", "steps"];
const REQUIRED_STEP = ["outcome"];
/** Outcomes that are not compared. */
const NOT_RUN = new Set(["N/A", "not verified"]);
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

/** A location: the case ID, the step (or null) and the field path, each apart (IDs contain dots). */
export const label = (id, step, field) =>
  `${id}${step === null ? "" : `#${step}`}${field.length === 0 ? "" : `.${field.join(".")}`}`;

/** `*` within one key or case ID: any characters. */
const wildcard = (glob, text) =>
  new RegExp(`^${glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*")}$`).test(text);

/** A dotted glob against a field path: `*` in a key is any characters, a `**` key any number of keys. */
export function fieldMatches(glob, field) {
  const g = glob === "" ? [] : glob.split(".");
  const go = (i, j) => {
    if (i === g.length) return j === field.length;
    if (g[i] === "**") {
      for (let k = j; k <= field.length; k++) if (go(i + 1, k)) return true;
      return false;
    }
    return j < field.length && wildcard(g[i], field[j]) && go(i + 1, j + 1);
  };
  return go(0, 0);
}

/** A schema entry's `case`: one glob or a list of them. */
const idMatches = (glob, id) => (Array.isArray(glob) ? glob : [glob]).some((g) => wildcard(g, id));

/** The schema entry that documents a field only `side` gives here, if any. */
function schemaEntry(schema, corpus, side, id, step, field) {
  return schema.find(
    (e) =>
      e.corpus === corpus &&
      e.side === side &&
      idMatches(e.case, id) &&
      (e.step === undefined ? step === null : e.step === "*" ? step !== null : e.step === step) &&
      fieldMatches(e.field, field),
  );
}

/** The fields a flow report declares not applicable at a step (null: the case), as paths. */
function declaredNa(report, step) {
  const out = [];
  for (const x of Array.isArray(report?.not_applicable) ? report.not_applicable : []) {
    if (typeof x?.field !== "string") continue;
    if ((x.step ?? null) !== step) continue;
    // A flow's `final` is reported as its post_state.
    out.push(
      x.field.startsWith("final.")
        ? ["post_state", ...x.field.slice(6).split(".")]
        : x.field.split("."),
    );
  }
  return out;
}

/**
 * Compares two reported values at a location. `ctx` holds the corpus, the
 * case ID and step, the schema list, the fields each side declares N/A
 * there, and the output lists.
 */
export function compareValues(ts, rs, field, ctx) {
  const { id, step } = ctx;
  const where = label(id, step, field);
  if (ts === undefined || rs === undefined) {
    const side = ts === undefined ? "sdk-rs" : "sdk-ts";
    const declared = (ts === undefined ? ctx.naTs : ctx.naRs).some(
      (p) => p.length <= field.length && p.every((k, i) => field[i] === k),
    );
    const entry = schemaEntry(ctx.schema, ctx.corpus, side, id, step, field);
    if (entry !== undefined) {
      ctx.out.schemaUsed.add(entry);
      ctx.out.oneSided.push({ id, step, field, side, label: where, entry: entry.why });
    } else if (declared)
      ctx.out.oneSided.push({ id, step, field, side, label: where, entry: "declared N/A" });
    else ctx.out.diffs.push({ id, step, field, label: where, kind: "one-sided", ts, rs });
    return;
  }
  if (isObject(ts) && isObject(rs)) {
    for (const k of [...new Set([...Object.keys(ts), ...Object.keys(rs)])].sort())
      compareValues(ts[k], rs[k], [...field, k], ctx);
    return;
  }
  // A frontier entry without extra ranges is its contiguous count (W §28.1).
  const isFrontier = field.length >= 2 && field[field.length - 2] === "frontier";
  const last = field[field.length - 1];
  const norm = (v) =>
    SET_FIELDS.has(last) && Array.isArray(v)
      ? [...v].map(stable).sort()
      : isFrontier && typeof v === "number"
        ? { contiguous: v, extra_ranges: [] }
        : v;
  if (stable(norm(ts)) !== stable(norm(rs)))
    ctx.out.diffs.push({ id, step, field, label: where, kind: "value", ts, rs });
}

const reasonsOf = (r) =>
  Array.isArray(r.not_applicable) || Array.isArray(r.not_verified)
    ? [...(r.not_applicable ?? []), ...(r.not_verified ?? [])]
        .map(
          (x) =>
            `${x.step === undefined ? "" : `step ${x.step}`}${x.field === undefined ? "" : ` ${x.field}`}: ${x.reason}`,
        )
        .join("; ")
    : (r.not_applicable ?? r.not_verified ?? r.reason);

/** One outcome (a case, or a flow step) against the other side's. */
function compareOutcome(ts, rs, ctx) {
  const { id, step, out } = ctx;
  if (ts === undefined || rs === undefined) {
    out.missing.push({
      id,
      step,
      label: label(id, step, []),
      side: ts === undefined ? "sdk-ts" : "sdk-rs",
    });
    return;
  }
  const flow = step === null && (Array.isArray(ts.steps) || Array.isArray(rs.steps));
  const notRun = (r) => NOT_RUN.has(r?.outcome);
  if (notRun(ts) || notRun(rs)) {
    const side = notRun(ts) && notRun(rs) ? "both" : notRun(ts) ? "sdk-ts" : "sdk-rs";
    out.na.push({
      id,
      step,
      label: label(id, step, []),
      side,
      kind: [ts, rs].some((r) => r.outcome === "not verified") ? "not verified" : "N/A",
      reason: [
        notRun(ts) ? `sdk-ts: ${reasonsOf(ts)}` : "",
        notRun(rs) ? `sdk-rs: ${reasonsOf(rs)}` : "",
      ]
        .filter(Boolean)
        .join(" / "),
      other: side === "both" ? "" : side === "sdk-ts" ? rs.outcome : ts.outcome,
    });
    // A flow is compared step by step even when a side calls it N/A in part.
    if (!flow) return;
  }
  const required = step !== null ? REQUIRED_STEP : flow ? REQUIRED_FLOW : REQUIRED_CASE;
  for (const k of required)
    for (const [side, r] of [
      ["sdk-ts", ts],
      ["sdk-rs", rs],
    ])
      if (!(k in r))
        out.diffs.push({
          id,
          step,
          field: [k],
          label: label(id, step, [k]),
          kind: `required, absent in ${side}`,
        });
  // A step's field N/A is declared in its flow's not_applicable list.
  const sub = {
    ...ctx,
    naTs: declaredNa(step === null ? ts : ctx.flowTs, step),
    naRs: declaredNa(step === null ? rs : ctx.flowRs, step),
  };
  for (const k of [...new Set([...Object.keys(ts), ...Object.keys(rs)])].sort()) {
    if (NOT_COMPARED.has(k) || k === "steps") continue;
    // A flow's outcome summarises its steps.
    if (k === "outcome" && flow) continue;
    if (k === "diagnostic" && (ts[k] === undefined || rs[k] === undefined)) continue;
    if (required.includes(k) && (!(k in ts) || !(k in rs))) continue;
    compareValues(ts[k], rs[k], [k], sub);
  }
  if (flow) {
    const byN = (steps) => new Map((steps ?? []).map((s) => [s.n, s]));
    const a = byN(ts.steps);
    const b = byN(rs.steps);
    for (const n of [...new Set([...a.keys(), ...b.keys()])].sort((x, y) => x - y))
      compareOutcome(a.get(n), b.get(n), { ...ctx, step: n, flowTs: ts, flowRs: rs });
  }
}

/** Compares one export file of both sides; `schema` is the documented schema differences. */
export function compareExports(name, ts, rs, schema = []) {
  const out = {
    name,
    problems: [],
    na: [],
    diffs: [],
    oneSided: [],
    missing: [],
    schemaUsed: new Set(),
  };
  for (const [side, x] of [
    ["sdk-ts", ts],
    ["sdk-rs", rs],
  ])
    if (x.format !== FORMAT) out.problems.push(`${side} ${name} is ${x.format}, not ${FORMAT}`);
  if (stable(ts.spec) !== stable(rs.spec))
    out.problems.push(`${name}: the spec pins differ: ${stable(ts.spec)} vs ${stable(rs.spec)}`);
  const ids = [...new Set([...Object.keys(ts.cases), ...Object.keys(rs.cases)])].sort();
  for (const id of ids)
    compareOutcome(ts.cases[id], rs.cases[id], { corpus: name, id, step: null, schema, out });
  out.cases = ids.length;
  const divergent = new Set([...out.diffs.map((d) => d.id), ...out.missing.map((m) => m.id)]);
  const isFlow = (id) => Array.isArray(ts.cases[id]?.steps) && Array.isArray(rs.cases[id]?.steps);
  const naCases = new Set(out.na.filter((n) => n.step === null && !isFlow(n.id)).map((n) => n.id));
  const naSteps = new Set(out.na.filter((n) => n.step !== null || isFlow(n.id)).map((n) => n.id));
  out.counts = {
    divergent: divergent.size,
    na: [...naCases].filter((id) => !divergent.has(id)).length,
    withNaSteps: [...naSteps].filter((id) => !divergent.has(id) && !naCases.has(id)).length,
    match: ids.filter((id) => !divergent.has(id) && !naCases.has(id) && !naSteps.has(id)).length,
  };
  return out;
}

/** Schema entries that covered nothing in any corpus. */
export function staleSchema(results, schema) {
  const used = new Set(results.flatMap((r) => [...r.schemaUsed]));
  return schema.filter((e) => !used.has(e));
}

const keyOf = (corpus, where) => `${corpus}:${where}`;

/** Matches divergences against the known list; returns unexplained ones and stale entries. */
export function explain(results, known) {
  const entries = new Map(known.map((k) => [keyOf(k.corpus, k.path), k]));
  const used = new Set();
  const unexplained = [];
  for (const r of results)
    for (const d of r.diffs) {
      const k = keyOf(r.name, d.label);
      if (entries.has(k)) used.add(k);
      else unexplained.push({ corpus: r.name, ...d });
    }
  const stale = known.filter((k) => !used.has(keyOf(k.corpus, k.path)));
  return { unexplained, stale };
}

const short = (v) => {
  const s = v === undefined ? "(absent)" : stable(v);
  return s.length > 120 ? `${s.slice(0, 117)}...` : s;
};
const cell = (s) => String(s ?? "").replaceAll("|", "\\|");

export function markdown(results, known, { unexplained, stale }, staleEntries = []) {
  const lines = ["# Identity differential: sdk-ts vs sdk-rs", ""];
  lines.push(
    "| Corpus | Cases | Match | Match, some steps N/A or not verified | Case N/A | Divergent | N/A / not verified entries | Documented one-sided fields |",
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
        `Missing in ${r.name}: ${r.missing.map((m) => `${m.label} (no ${m.side} outcome)`).join(", ")}`,
        "",
      );
  }
  lines.push("## Divergences", "");
  const all = results.flatMap((r) => r.diffs.map((d) => ({ corpus: r.name, ...d })));
  if (all.length === 0) lines.push("None.", "");
  else {
    lines.push("| Corpus | Where | Kind | sdk-ts | sdk-rs | Right by the text | Why |");
    lines.push("|---|---|---|---|---|---|---|");
    const byKey = new Map(known.map((k) => [keyOf(k.corpus, k.path), k]));
    for (const d of all) {
      const k = byKey.get(keyOf(d.corpus, d.label));
      lines.push(
        `| ${d.corpus} | \`${cell(d.label)}\` | ${d.kind} | \`${cell(short(d.ts))}\` | \`${cell(short(d.rs))}\` | ${k?.right ?? "**unexplained**"} | ${cell(k?.why)} |`,
      );
    }
    lines.push("");
  }
  lines.push("## N/A and not verified", "");
  const na = results.flatMap((r) => r.na.map((n) => ({ corpus: r.name, ...n })));
  if (na.length === 0) lines.push("None.", "");
  else {
    lines.push("| Corpus | Case / step | Kind | On | Other side | Reason |");
    lines.push("|---|---|---|---|---|---|");
    for (const n of na)
      lines.push(
        `| ${n.corpus} | \`${cell(n.label)}\` | ${n.kind} | ${n.side} | ${cell(n.other)} | ${cell(n.reason)} |`,
      );
    lines.push("");
  }
  lines.push("## Documented one-sided fields (differential-schema.json, declared N/A)", "");
  for (const r of results) {
    const counts = new Map();
    for (const o of r.oneSided) {
      const key = `${o.side}: ${o.entry}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    if (counts.size === 0) continue;
    lines.push(`${r.name}:`, "");
    for (const [k, n] of [...counts].sort()) lines.push(`- ${n} × ${cell(k)}`);
    lines.push("");
  }
  if (unexplained.length > 0 || stale.length > 0 || staleEntries.length > 0) {
    lines.push("## Problems", "");
    for (const u of unexplained) lines.push(`- unexplained: ${u.corpus} \`${u.label}\``);
    for (const s of stale) lines.push(`- stale explanation: ${s.corpus} \`${s.path}\``);
    for (const s of staleEntries)
      lines.push(`- stale schema entry: ${s.corpus} ${s.case} ${s.step ?? ""} ${s.field}`);
    lines.push("");
  }
  return lines.join("\n");
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i < 0 ? undefined : process.argv[i + 1];
}

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
export const loadSchema = () =>
  readJson(join(ROOT, "conformance/identity/differential-schema.json")).differences;

function main() {
  const tsDir = arg("--ts");
  const rsDir = arg("--rs");
  if (tsDir === undefined || rsDir === undefined) {
    process.stderr.write("usage: identity-differential.mjs --ts <dir> --rs <dir> [--out <file>]\n");
    process.exit(2);
  }
  const schema = loadSchema();
  const read = (dir, f) => readJson(join(resolve(dir), f));
  const results = FILES.map((f) => compareExports(f, read(tsDir, f), read(rsDir, f), schema));
  const known = readJson(join(ROOT, "conformance/identity/differential-known.json")).divergences;
  const verdict = explain(results, known);
  const staleEntries = staleSchema(results, schema);
  const text = markdown(results, known, verdict, staleEntries);
  const out = arg("--out");
  if (out !== undefined) writeFileSync(out, `${text}\n`);
  process.stdout.write(`${text}\n`);
  const problems = results.flatMap((r) => [...r.problems, ...r.missing.map((m) => m.label)]);
  const bad = problems.length + verdict.unexplained.length + verdict.stale.length;
  process.exit(bad + staleEntries.length === 0 ? 0 : 1);
}

function selfTest() {
  const fail = (m) => {
    process.stderr.write(`identity-differential self-test: ${m}\n`);
    process.exit(1);
  };
  const spec = { repository: "r", tag: "t", commit: "c" };
  const mk = (cases) => ({ format: FORMAT, implementation: "x", spec, cases });
  const row = (active) => ({ root: "OWNER", active, leaf: "CERT_A" });
  const base = () => ({
    a: {
      outcome: "accept",
      accepted_ids: ["01"],
      post_state: { devices: { DEV_A: row(true), DEV_B: row(true) }, owner: "OWNER" },
    },
    b: { outcome: "AUTHORIZATION_FAILED", accepted_ids: [], post_state: null },
    c: { outcome: "accept", accepted_ids: ["02"], post_state: { plaintext_hex: "00" } },
    f: {
      outcome: "accept",
      not_applicable: [],
      post_state: {},
      steps: [{ n: 1, outcome: "accept", phase: "pending" }],
    },
  });
  const clone = (x) => JSON.parse(JSON.stringify(x));
  const run = (ts, rs, schema = []) => compareExports("identity-wire.json", mk(ts), mk(rs), schema);
  const labels = (r) => r.diffs.map((d) => d.label).join();

  // The same report on both sides matches.
  const same = run(base(), base());
  if (same.diffs.length + same.missing.length !== 0 || same.counts.match !== 4)
    fail(`identical exports: ${stable(same.diffs)} ${stable(same.counts)}`);

  // A row missing from a state table is a divergence (review of sdk-ts#19, P2-1).
  const noDevA = clone(base());
  delete noDevA.a.post_state.devices.DEV_A;
  const r1 = run(noDevA, base());
  if (labels(r1) !== "a.post_state.devices.DEV_A" || r1.counts.divergent !== 1)
    fail(`a missing device row: ${labels(r1)} ${stable(r1.counts)}`);

  // A missing required field, a missing post-state field or a null post-state is a divergence too.
  const noIds = clone(base());
  delete noIds.a.accepted_ids;
  if (labels(run(noIds, base())) !== "a.accepted_ids") fail("a missing accepted_ids");
  const noOutcome = clone(base());
  delete noOutcome.b.outcome;
  if (labels(run(base(), noOutcome)) !== "b.outcome") fail("a missing outcome");
  const noPlain = clone(base());
  delete noPlain.c.post_state.plaintext_hex;
  if (labels(run(noPlain, base())) !== "c.post_state.plaintext_hex") fail("a missing plaintext");
  const nullPost = clone(base());
  nullPost.c.post_state = null;
  if (labels(run(nullPost, base())) !== "c.post_state") fail("a null post-state");

  // Values that differ, in a case and in a step.
  const other = clone(base());
  other.b.outcome = "MALFORMED_MESSAGE";
  other.f.steps[0].phase = "complete";
  if (labels(run(base(), other)) !== "b.outcome,f#1.phase")
    fail(`values ${labels(run(base(), other))}`);

  // A documented schema difference covers its side and field only; an unused entry is stale.
  const extra = clone(base());
  extra.a.post_state.devices.DEV_A.issuers = [];
  const schema = [
    {
      corpus: "identity-wire.json",
      case: "a",
      field: "post_state.devices.*.issuers",
      side: "sdk-ts",
      why: "s1",
    },
    { corpus: "identity-wire.json", case: "z*", field: "post_state", side: "sdk-rs", why: "s2" },
  ];
  const r2 = run(extra, base(), schema);
  if (r2.diffs.length !== 0 || r2.oneSided.length !== 1) fail(`schema entry ${stable(r2.diffs)}`);
  if (
    staleSchema([r2], schema)
      .map((e) => e.why)
      .join() !== "s2"
  )
    fail("stale schema entry");
  if (labels(run(base(), extra, schema)) !== "a.post_state.devices.DEV_A.issuers")
    fail("a schema entry of the other side");

  // A field a side declares N/A for a step may be absent on that side.
  const naField = clone(base());
  naField.f.not_applicable = [{ step: 1, field: "phase", reason: "why" }];
  delete naField.f.steps[0].phase;
  if (run(naField, base()).diffs.length !== 0) fail("a declared N/A field");

  // N/A and not verified are listed, not compared.
  const na = clone(base());
  na.b = { outcome: "N/A", not_applicable: "why" };
  na.f.steps[0] = { n: 1, outcome: "not verified", not_verified: "harness" };
  const r3 = run(na, base());
  if (
    r3.diffs.length !== 0 ||
    r3.na.map((n) => `${n.label}:${n.kind}`).join() !== "b:N/A,f#1:not verified"
  )
    fail(`na ${stable(r3.na)} ${stable(r3.diffs)}`);

  // Known divergences: explained, unexplained, stale.
  const v = explain(
    [run(base(), other)],
    [
      { corpus: "identity-wire.json", path: "b.outcome", right: "sdk-ts", why: "§1" },
      { corpus: "identity-wire.json", path: "gone.outcome", right: "sdk-ts", why: "§2" },
    ],
  );
  if (v.unexplained.map((u) => u.label).join() !== "f#1.phase") fail(`unexplained ${stable(v)}`);
  if (v.stale.map((s) => s.path).join() !== "gone.outcome") fail(`stale ${stable(v.stale)}`);

  // Case IDs with dots (flow.*) are counted as themselves, not by their prefix.
  const plain = (outcome) => ({ outcome, accepted_ids: [], post_state: null });
  const dotted = run(
    { "flow.a": plain("accept"), "flow.b": plain("accept"), "flow.c": plain("accept") },
    {
      "flow.a": plain("AUTHORIZATION_FAILED"),
      "flow.b": plain("AUTHORIZATION_FAILED"),
      "flow.c": plain("accept"),
    },
  );
  if (stable(dotted.counts) !== stable({ divergent: 2, na: 0, withNaSteps: 0, match: 1 }))
    fail(`dotted IDs ${stable(dotted.counts)}`);

  if (
    !fieldMatches("post_state.**", ["post_state", "a", "b"]) ||
    fieldMatches("post_state.*", ["post_state", "a", "b"]) ||
    !fieldMatches("roster.*_conflict_set", ["roster", "k.x_conflict_set"]) ||
    fieldMatches("roster.*_conflict_set", ["roster", "k"])
  )
    fail("field globs");
  const pins = compareExports("x", mk({}), { ...mk({}), spec: { ...spec, commit: "d" } });
  if (pins.problems.length !== 1) fail("differing spec pins are not a problem");
  process.stdout.write("identity-differential self-test: ok\n");
}

if (process.argv.includes("--self-test")) selfTest();
else if (process.argv[1] === fileURLToPath(import.meta.url)) main();

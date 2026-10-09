// The shared sections corpus in the shape these tests read
// (LFCP-02-107). SHARED-SECTIONS-TEST-VECTORS-01 moved to
// lfcp-vector-format/1 after mvp-0.2-baseline.1; every value kept its
// value and moved (spec migrations/vector-format-1/shared-sections-01.mapping.json),
// and its byte records went from standard base64 to unpadded base64url.
// A suite in that format is read back into the earlier shape, so one test
// runs at either baseline. JavaScript with hand-written types
// (corpus-format.d.mts), like spec.mjs.

const CORPUS = "test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json";

/** Every { b64url } byte record, at any depth, as { base64 } of the same bytes. */
function toBase64Records(value) {
  if (Array.isArray(value)) return value.map(toBase64Records);
  if (value === null || typeof value !== "object") return value;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (k === "b64url" && typeof v === "string") {
      const std = v.replace(/-/g, "+").replace(/_/g, "/");
      out.base64 = std + "=".repeat((4 - (std.length % 4)) % 4);
    } else out[k] = toBase64Records(v);
  }
  return out;
}

/** A suite in lfcp-vector-format/1 in the mvp-0.2-baseline.1 shape (the mapping, inverted). */
export function legacySectionsSuite(suite) {
  if (suite.format !== "lfcp-vector-format/1") return suite;
  const c = suite.suite.conventions;
  const put = (o, k, v) => {
    if (v !== undefined) o[k] = v;
  };
  return toBase64Records({
    schema_version: 1,
    suite: suite.suite.id,
    date: c.date,
    status: c.status,
    profile: suite.suite.specification.profile,
    engine: { package: c.engine_package, version: c.engine_version, role: c.engine_role },
    wire_coverage: c.wire_coverage,
    identities: suite.fixtures.identities,
    cases: suite.cases.map((k) => {
      const out = { id: k.id, title: k.description };
      const i = k.inputs ?? {};
      const e = k.expected ?? {};
      put(out, "coverage", e.coverage);
      put(out, "notes", e.notes);
      put(out, "base_snapshot", i.base_snapshot);
      put(out, "base_changes", i.base_changes);
      put(out, "branches", i.branches);
      put(out, "after_merge", i.after_merge);
      put(out, "assertions", e.requirements);
      put(out, "expected", e.state);
      put(out, "expected_heads", e.heads);
      put(out, "reference_snapshot", e.reference_snapshot);
      put(out, "reference_snapshot_plaintext", e.reference_snapshot_plaintext);
      return out;
    }),
  });
}

/** The corpus of the spec checkout `spec` (openSpec()), in the shape the tests read. */
export function readSectionsCorpus(spec) {
  return legacySectionsSuite(spec.readJson(CORPUS));
}

// The sdk-ts adapter for SHARED-SECTIONS-TEST-VECTORS-01's independent
// adapter interface (generator/verify-vectors.mjs --adapter, §9 of the
// suite's document), LFCP-02-018. It replays a case's changes through the
// production SectionReplica (receiveChanges: the inherited and the §14.1
// admission) and reports the normalized state from the production tree,
// validation and document. It reads no expected value.
//
// Run by the reference verifier from a spec checkout, after `pnpm build`
// here:
//   node test-vectors/shared-sections-01/generator/verify-vectors.mjs \
//     test-vectors/shared-sections-01 --adapter <sdk-ts>/conformance/shared-sections/adapter.mjs
//
// Test-only Node code, outside the portable packages.

import { fromHex, principalId, resourceId } from "@openlfcp/core";
import { checkSnapshotExpansion, SNAPSHOT_LIMITS_FLOOR } from "@openlfcp/shared-objects";
import { SectionDocument, SectionReplica } from "@openlfcp/shared-objects/sections";

/** SHARED-OBJECTS-PROFILE-01 §13.1: the Snapshot floor of rows and group sums. */
const FLOOR = 262144;

const bytes = (record) => Uint8Array.from(atob(record.base64), (c) => c.charCodeAt(0));

/** JSON with object keys sorted. */
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, canonical(value[k])]),
    );
  return value;
}

/**
 * §13.1 counts of the full save, measured by the production Snapshot check
 * with limits raised so that it counts instead of refusing: the largest
 * column's rows and the sum of the group columns.
 */
function snapshotCounts(save) {
  const unlimited = Object.fromEntries(
    Object.keys(SNAPSHOT_LIMITS_FLOOR).map((k) => [k, Number.MAX_SAFE_INTEGER]),
  );
  const e = checkSnapshotExpansion(save, unlimited);
  return {
    rows: e.maxRows,
    group_sum: e.groupSum,
    within_floor: e.maxRows <= FLOOR && e.groupSum <= FLOOR,
  };
}

/**
 * input: { id, profile, identities, base_snapshot, base_changes, branches: {A, B}, after_merge },
 * and, for sdk-ts's own runs, `delivery`: "normal" (the default, as the
 * verifier calls it), "reverse" (every change twice, in reverse order) or
 * "checkpoint" (the base Snapshot, then the branches' changes).
 * Returns the case's normalized state, in the corpus's field names.
 */
export async function runCase(input) {
  const { identities } = input;
  const resource = resourceId(fromHex(identities.resource_hex));
  const principal = (name) => principalId(fromHex(identities.actors[name].principal_hex));
  const all = [
    ...input.base_changes,
    ...input.branches.A,
    ...input.branches.B,
    ...input.after_merge,
  ];
  const unit = (ch) => ({
    bytes: bytes(ch),
    ...(ch.signer === undefined ? {} : { signer: principal(ch.signer) }),
  });
  const opts = { resource, principal: principal("C") };
  const delivery = input.delivery ?? "normal";
  const replica =
    delivery === "checkpoint"
      ? SectionReplica.fromSave(bytes(input.base_snapshot), opts, "local-state")
      : SectionReplica.empty(opts);
  const units =
    delivery === "reverse"
      ? [...all].reverse().flatMap((ch) => [unit(ch), unit(ch)])
      : delivery === "checkpoint"
        ? [...input.branches.A, ...input.branches.B, ...input.after_merge].map(unit)
        : all.map(unit);
  const received = replica.receiveChanges(units);
  const tree = replica.tree();
  const state = replica.toJSON();
  const nodes = state.nodes ?? {};
  const objects = state.objects ?? {};
  const doc = SectionDocument.fromSave(replica.save(), "local-state");
  const task = identities.ids.task;
  const para = identities.ids.para;
  return {
    classification: tree.classification,
    tree: tree.tree.map((e) => ({ id: e.id, parent: e.parent, depth: e.depth, kind: e.kind })),
    hidden: [...tree.hidden],
    invalid: tree.invalid.map((x) => ({ id: x.id, diagnostic: x.diagnostic })),
    recovery: tree.recovery.map((x) => ({ id: x.id, code: x.code })),
    retainedConcurrentEdits: [...tree.retainedConcurrentEdits],
    scalarConflicts: tree.scalarConflicts.map((x) => ({
      id: x.id,
      field: x.field,
      values: [...x.values],
    })),
    ...(tree.collisions.length > 0 ? { collisions: [...tree.collisions] } : {}),
    texts: Object.fromEntries(
      Object.keys(nodes)
        .sort()
        // Every node with a visible text value, as the corpus's inspector reports them.
        .filter((n) => nodes[n].text !== undefined)
        .map((n) => [n, nodes[n].text]),
    ),
    tasks: Object.fromEntries(
      Object.keys(objects)
        .sort()
        .map((t) => [t, canonical(objects[t])]),
    ),
    slotCount: Object.keys(state.placements ?? {}).length,
    nodeCount: Object.keys(nodes).length,
    types: {
      taskTitleScalar:
        objects[task] === undefined ||
        doc.valueTypes(["objects", task, "title"]).every((t) => t === "str"),
      paragraphText:
        nodes[para] === undefined || doc.valueTypes(["nodes", para, "text"]).includes("text"),
    },
    // One entry per change: a duplicate unit of a refused change is refused again.
    refused: received.refused
      .filter((x, i, all) => !x.held && all.findIndex((y) => y.hash === x.hash) === i)
      .map((x) => ({ change: x.hash, diagnostic: x.diagnostic })),
    held: [...received.waiting].sort(),
    snapshot: snapshotCounts(replica.save()),
  };
}

// Runs the SHARED-OBJECTS-TEST-VECTORS-01 behavioral scenarios (S01-S16)
// through the sdk-ts Automerge binding (LFCP-031): every branch is a
// semantic intent applied by its fixture actor's replica, branches "from
// base" run concurrently and are merged by exchanging changes, and the
// merged replica is what the expected values are checked against.

import { fromHex, type ObjectId, principalId, resourceId, toHex } from "@openlfcp/core";
import {
  deriveActorId,
  type Json,
  type ReplicaIntent,
  resolveFieldConflict,
  type ScalarField,
  SharedObjectsReplica,
  type Task,
} from "@openlfcp/shared-objects";
import type { HandlerContext, VectorCase } from "../runner.js";
import { corpusScenario } from "./corpus.js";

interface Fixtures {
  readonly resource_a_hex: string;
  readonly principals: Readonly<Record<string, { id_hex: string; actor_a_hex: string }>>;
  readonly objects: Readonly<Record<string, string>>;
}

interface Branch {
  readonly actor?: string;
  readonly from?: string;
  readonly intent?: string;
  readonly operation?: string;
  readonly args?: Record<string, Json>;
  readonly object?: Record<string, Json>;
  readonly writes?: Record<string, Json>;
  readonly tag?: string;
  readonly principal?: string;
}

export interface ScenarioRun {
  readonly replica: SharedObjectsReplica;
  /** S14: the logical root right before the snapshot, and right after loading it. */
  readonly snapshot?: { readonly before: Json; readonly loaded: Json };
}

const fixturesOf = (context: HandlerContext): Fixtures =>
  context.suite.fixtures as unknown as Fixtures;

function optionsOf(fixtures: Fixtures, name: string) {
  const p = fixtures.principals[name];
  if (p === undefined) throw new Error(`unknown fixture principal ${name}`);
  const options = {
    resource: resourceId(fromHex(fixtures.resource_a_hex)),
    principal: principalId(fromHex(p.id_hex)),
  };
  // The binding's §8 actor is the fixture actor.
  if (toHex(deriveActorId(options.resource, options.principal)) !== p.actor_a_hex)
    throw new Error(`the actor of ${name} differs from the fixture actor_a_hex`);
  return options;
}

/** The semantic intent a vector branch states (§59-§69). */
function intentOf(branch: Branch, id: ObjectId): ReplicaIntent {
  const w = branch.writes ?? {};
  const str = (field: string): string => String(w[field]);
  switch (branch.intent) {
    case "task.create":
      return { intent: "task.create", task: branch.args as unknown as Task };
    case "task.set_title":
      return { intent: "task.set_title", id, title: str("title") };
    case "task.set_status":
      return { intent: "task.set_status", id, status: str("status") as Task["status"] };
    case "task.complete":
      return {
        intent: "task.complete",
        id,
        ...(w.completion_date !== undefined ? { completionDate: str("completion_date") } : {}),
      };
    case "task.cancel":
      return { intent: "task.cancel", id };
    case "task.set_due":
      return { intent: "task.set_due", id, date: str("due") };
    case "task.delete":
      return { intent: "task.delete", id };
    case "task.restore":
      return { intent: "task.restore", id };
    case "task.resolve_field_conflict": {
      const [field, ...more] = Object.keys(w);
      if (field === undefined || more.length > 0)
        throw new Error(`a field-conflict resolution writes one field: ${JSON.stringify(w)}`);
      return resolveFieldConflict(id, field as ScalarField, w[field] === null ? null : str(field));
    }
    case "task.add_tag":
    case "task.remove_tag":
      return { intent: branch.intent, id, tag: String(branch.tag) };
    case "task.add_assignee":
    case "task.remove_assignee":
      return { intent: branch.intent, id, assignee: String(branch.principal) as never };
  }
  if (branch.operation === "create")
    return { intent: "task.create", task: branch.object as unknown as Task };
  throw new Error(`unsupported branch ${JSON.stringify(branch)}`);
}

/** Every change of every replica, merged into one replica of `name`. */
function merge(fixtures: Fixtures, name: string, replicas: readonly SharedObjectsReplica[]) {
  const { replica, unapplied } = SharedObjectsReplica.fromChanges(
    replicas.flatMap((r) => r.changes()),
    optionsOf(fixtures, name),
  );
  if (unapplied.length > 0) throw new Error(`${unapplied.length} merged changes lack dependencies`);
  return replica;
}

const fork = (fixtures: Fixtures, r: SharedObjectsReplica, name: string) =>
  merge(fixtures, name, [r]);

function apply(replica: SharedObjectsReplica, intent: ReplicaIntent): void {
  if (replica.apply(intent) === null) throw new Error(`${intent.intent} made no change`);
}

/** The base replica of a scenario, by andrey unless the scenario builds on another. */
function baseOf(c: VectorCase, context: HandlerContext): ScenarioRun {
  const fixtures = fixturesOf(context);
  const base = (c.inputs?.base_state ?? {}) as Record<string, Json>;
  if (typeof base.derived_from === "string") {
    // S04: continue from the merged state of another scenario.
    const source = context.caseById(base.derived_from.split(/\s+/)[0] as string);
    if (source === undefined) throw new Error(`unknown scenario ${base.derived_from}`);
    return runScenario(source, context);
  }
  if (typeof base.build === "string") {
    // S14: "Apply S01 then S06": S06's branches on S01's state.
    const s01 = runScenario(context.caseById("S01") as VectorCase, context).replica;
    const s06 = (context.caseById("S06")?.inputs?.branches ?? []) as Branch[];
    const id = fixtures.objects.task_1 as ObjectId;
    const forks = s06.map((b) => {
      const r = fork(fixtures, s01, String(b.actor));
      apply(r, intentOf(b, id));
      return r;
    });
    return { replica: merge(fixtures, "andrey", forks) };
  }
  const { replica } = SharedObjectsReplica.create(optionsOf(fixtures, "andrey"));
  const objects: Record<string, Json> =
    typeof base.id === "string"
      ? { [base.id]: base }
      : base.task !== undefined
        ? { [String((base.task as Record<string, Json>).id)]: base.task }
        : ((base.objects as Record<string, Json> | undefined) ?? {});
  for (const object of Object.values(objects)) {
    const o = object as Record<string, Json>;
    if (o.type === "task") {
      apply(replica, { intent: "task.create", task: o as unknown as Task });
    } else {
      // S12: an object type this client does not understand can only come
      // from another client, so it arrives as that client's change: the
      // corpus base change made by the reference generator.
      const change = corpusScenario(c.id).changes.find((x) => x.label === `${c.id}.base`);
      if (change === undefined) throw new Error(`no ${c.id}.base change in the corpus`);
      const result = replica.receiveChange(fromHex(change.change_hex));
      if (result.status !== "applied") throw new Error(`${c.id}.base was ${result.status}`);
    }
  }
  return { replica };
}

const runs = new WeakMap<VectorCase, ScenarioRun>();

/** The merged outcome of one behavioral scenario. */
export function runScenario(c: VectorCase, context: HandlerContext): ScenarioRun {
  const done = runs.get(c);
  if (done !== undefined) return done;
  const fixtures = fixturesOf(context);
  const id = fixtures.objects.task_1 as ObjectId;
  let { replica, snapshot } = baseOf(c, context);
  const forks: SharedObjectsReplica[] = [];
  for (const branch of (c.inputs?.branches ?? []) as Branch[]) {
    if (branch.operation === "load-save-roundtrip-without-understanding-type") {
      replica = SharedObjectsReplica.fromSave(
        replica.save(),
        optionsOf(fixtures, String(branch.actor)),
      );
      continue;
    }
    if (branch.operation === "snapshot_save_load_roundtrip") {
      const before = replica.root();
      replica = SharedObjectsReplica.fromSnapshot(
        replica.snapshot(),
        optionsOf(fixtures, "andrey"),
      );
      snapshot = { before, loaded: replica.root() };
      continue;
    }
    const r = fork(fixtures, replica, String(branch.actor));
    apply(r, intentOf(branch, id));
    if (branch.from === "base") forks.push(r);
    else replica = r; // from the merged state, or after the snapshot
  }
  if (forks.length > 0) replica = merge(fixtures, "andrey", forks);
  const run: ScenarioRun = snapshot === undefined ? { replica } : { replica, snapshot };
  runs.set(c, run);
  return run;
}

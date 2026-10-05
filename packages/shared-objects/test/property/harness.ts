// LFCP-037: the multi-replica harness of the CRDT property suite.
//
// Replicas are real SharedObjectsReplica instances driven only through the
// public API: semantic intents in (apply), Automerge change bytes out, and
// changes delivered with receiveChange in any order, duplicated or delayed
// (a change whose dependencies are missing waits in the replica's buffer).
//
// The oracle is independent of Automerge. It records, for every change,
// which changes its replica had applied when the change was made (its
// causal past) and which registers it wrote: a scalar field, or one member
// of `tags` or `assignees`. A register's surviving writes are those no
// later write to it saw (multi-value register, SHARED-OBJECTS-PROFILE-01
// §44-§45); the register is present when a surviving write is a put
// (add-wins for collection members, §41, §43), and its concurrent values
// are the values of the surviving puts. That is checked against each
// replica's logical state and conflict sets, never against bytes.
//
// Network transport, signatures and LFCP authorization play no part: this
// suite proves CRDT and profile behavior only.

import { type ObjectId, type PrincipalId, principalId, resourceId, toHex } from "@openlfcp/core";
import {
  checkChange,
  type Json,
  type LocalChange,
  principalRef,
  type ReplicaIntent,
  SCALAR_FIELDS,
  type ScalarField,
  SharedObjectsReplica,
  type TaskIntent,
} from "../../src/index.js";

export const RESOURCE = resourceId(Uint8Array.from({ length: 32 }, (_, i) => 0x37 ^ i));

/** Up to five writers, each with its own Principal and so its own §8 actor. */
export const PRINCIPALS: readonly PrincipalId[] = [0, 1, 2, 3, 4].map((n) =>
  principalId(Uint8Array.from({ length: 32 }, (_, i) => (n * 41 + i * 7 + 1) & 0xff)),
);
export const REPLICA_NAMES = ["r0", "r1", "r2", "r3", "r4"] as const;

/** The small value pools generators draw from: small pools make concurrent writes collide. */
export const POOL = {
  title: ["Plan", "Draft", "Review"],
  status: ["todo", "in_progress", "done", "cancelled"],
  priority: ["low", "normal", "high"],
  date: ["2026-10-01", "2026-10-15", "2026-11-02"],
  tag: ["api", "ui", "urgent"],
  lifecycle: ["active", "deleted"],
} as const;
export const ASSIGNEES = PRINCIPALS.slice(0, 3).map((p) => principalRef(p));

/** A canonical UUIDv7 Object ID for the n-th created object. */
export const objectIdOf = (n: number): ObjectId =>
  `0190a5c0-0000-7000-8000-${n.toString(16).padStart(12, "0")}` as ObjectId;

// ---------------------------------------------------------------- programs

/** One step of a generated program; fields are raw choices, interpreted modulo the live state. */
export type Step =
  | {
      readonly t: "op";
      readonly r: number;
      readonly o: number;
      readonly k: number;
      readonly v: number;
    }
  | { readonly t: "create"; readonly r: number; readonly v: number }
  | {
      readonly t: "sync";
      readonly from: number;
      readonly to: number;
      readonly take: number;
      readonly seed: number;
      readonly dup: boolean;
    };

export interface Program {
  readonly replicas: number;
  readonly objects: number;
  readonly steps: readonly Step[];
  readonly finalSeed: number;
}

/** A deterministic PRNG (mulberry32) for delivery orders. */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function shuffled<T>(items: readonly T[], random: () => number): T[] {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [out[i], out[j]] = [out[j] as T, out[i] as T];
  }
  return out;
}

// ---------------------------------------------------------------- oracle

/** One register write: a field of an object, or a collection member ("tags/x"). */
interface Write {
  readonly object: string;
  readonly register: string;
  readonly put: boolean;
  readonly value: Json;
}

interface OracleChange {
  readonly hash: string;
  /** Changes applied at the writing replica when it wrote this one. */
  readonly past: ReadonlySet<string>;
  readonly writes: readonly Write[];
  readonly label: string;
  readonly replica: string;
}

/** The expected logical state of every object over a set of changes. */
export interface Expected {
  /** Object ID -> register -> surviving put values (sorted JSON); absent registers omitted. */
  readonly objects: ReadonlyMap<string, ReadonlyMap<string, readonly Json[]>>;
}

/**
 * JSON with object keys sorted. Logical state has no key order, but a
 * writer's Automerge document lists a key it deleted and put again (G-SC4)
 * last while a receiver lists it in place, so plain JSON.stringify differs.
 */
export function canonical(value: unknown): string {
  return JSON.stringify(value, (_, v: unknown) =>
    v !== null && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v as object).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : v,
  );
}

const byJson = (a: Json, b: Json): number => {
  const [x, y] = [JSON.stringify(a), JSON.stringify(b)];
  return x < y ? -1 : x > y ? 1 : 0;
};

export class Oracle {
  readonly changes = new Map<string, OracleChange>();

  record(change: OracleChange): void {
    this.changes.set(change.hash, change);
  }

  /** The expected state over `known` (a causally closed set of change hashes). */
  expected(known: ReadonlySet<string>): Expected {
    const writes = new Map<string, { change: OracleChange; write: Write }[]>();
    for (const hash of known) {
      const change = this.changes.get(hash);
      if (change === undefined) continue;
      for (const write of change.writes) {
        const key = `${write.object}\u0000${write.register}`;
        const list = writes.get(key) ?? [];
        list.push({ change, write });
        writes.set(key, list);
      }
    }
    const objects = new Map<string, Map<string, Json[]>>();
    for (const list of writes.values()) {
      const surviving = list.filter(
        (w) => !list.some((other) => other.change.past.has(w.change.hash)),
      );
      const puts = surviving.filter((w) => w.write.put).map((w) => w.write.value);
      const first = list[0] as { write: Write };
      const fields = objects.get(first.write.object) ?? new Map<string, Json[]>();
      objects.set(first.write.object, fields);
      if (puts.length > 0) fields.set(first.write.register, puts.sort(byJson));
    }
    return { objects };
  }

  /** Whether `register` of `object` is present (has a surviving put) over `known`. */
  present(known: ReadonlySet<string>, object: string, register: string): boolean {
    return this.expected(known).objects.get(object)?.has(register) ?? false;
  }
}

// ---------------------------------------------------------------- observation

/** What a replica shows of one Task: every scalar register's values and the collection members. */
export interface ObservedTask {
  readonly fields: Readonly<Record<string, readonly Json[]>>;
  readonly tags: readonly string[];
  readonly assignees: readonly string[];
}
export type Observation = Readonly<Record<string, ObservedTask>>;

export function observe(replica: SharedObjectsReplica): Observation {
  const out: Record<string, ObservedTask> = {};
  for (const id of replica.objectIds()) {
    const view = replica.task(id);
    if (view === undefined) continue;
    const fields: Record<string, readonly Json[]> = {};
    for (const f of SCALAR_FIELDS)
      if (view.fields[f].values.length > 0) fields[f] = [...view.fields[f].values].sort(byJson);
    out[id] = { fields, tags: [...view.tags].sort(), assignees: [...view.assignees].sort() };
  }
  return out;
}

/** The observation the oracle expects. */
export function expectedObservation(expected: Expected): Observation {
  const out: Record<string, ObservedTask> = {};
  for (const [id, registers] of expected.objects) {
    const fields: Record<string, readonly Json[]> = {};
    const tags: string[] = [];
    const assignees: string[] = [];
    for (const [register, values] of registers) {
      if (register.startsWith("tags/")) tags.push(register.slice(5));
      else if (register.startsWith("assignees/")) assignees.push(register.slice(10));
      else if ((SCALAR_FIELDS as readonly string[]).includes(register)) fields[register] = values;
    }
    out[id] = { fields, tags: tags.sort(), assignees: assignees.sort() };
  }
  return out;
}

/** Every difference between an observation and the expected one, as readable lines. */
export function differences(actual: Observation, expected: Observation): string[] {
  const out: string[] = [];
  const ids = [...new Set([...Object.keys(actual), ...Object.keys(expected)])].sort();
  for (const id of ids) {
    const a = actual[id];
    const e = expected[id];
    if (a === undefined || e === undefined) {
      out.push(`${id}: object ${a === undefined ? "missing" : "unexpected"}`);
      continue;
    }
    for (const f of SCALAR_FIELDS) {
      const [x, y] = [JSON.stringify(a.fields[f] ?? []), JSON.stringify(e.fields[f] ?? [])];
      if (x !== y) out.push(`${id}.${f}: actual ${x}, expected ${y}`);
    }
    for (const set of ["tags", "assignees"] as const) {
      const [x, y] = [JSON.stringify(a[set]), JSON.stringify(e[set])];
      if (x !== y) out.push(`${id}.${set}: actual ${x}, expected ${y}`);
    }
  }
  return out;
}

// ---------------------------------------------------------------- the world

interface Node {
  readonly name: string;
  readonly principal: PrincipalId;
  readonly replica: SharedObjectsReplica;
  /** Hashes this replica has applied. */
  readonly applied: Set<string>;
  /** Changes delivered whose dependencies were missing: delayed until they apply. */
  readonly pending: Map<string, Uint8Array>;
}

/** A fault injected into what the checker observes, to test the tests (LFCP-037). */
export type Fault = (observation: Observation, world: World) => Observation;

export class World {
  readonly nodes: Node[];
  readonly oracle = new Oracle();
  /** Every change ever made, by hash. */
  readonly bytes = new Map<string, Uint8Array>();
  /** Created objects, in creation order, with the hash of their creating change. */
  readonly objects: { id: string; created: string }[] = [];
  /** The program log, for failure reports. */
  readonly log: string[] = [];
  #nextObject = 0;

  constructor(replicas: number, objects: number) {
    const { replica, change } = SharedObjectsReplica.create({
      resource: RESOURCE,
      principal: PRINCIPALS[0] as PrincipalId,
    });
    this.nodes = [];
    this.nodes.push(this.#node(0, replica));
    this.#recordLocal(this.nodes[0] as Node, change, []);
    for (let i = 1; i < replicas; i++) {
      const node = this.#node(
        i,
        SharedObjectsReplica.empty({ resource: RESOURCE, principal: PRINCIPALS[i] as PrincipalId }),
      );
      this.nodes.push(node);
    }
    for (let n = 0; n < objects; n++) this.create(0, n);
    // Everyone starts from the same base: the Resource and its first objects.
    for (let i = 1; i < replicas; i++) this.deliver(i, [...this.bytes.keys()]);
    this.log.push(`base: ${replicas} replicas, ${objects} objects, all delivered`);
  }

  #node(i: number, replica: SharedObjectsReplica): Node {
    return {
      name: REPLICA_NAMES[i] as string,
      principal: PRINCIPALS[i] as PrincipalId,
      replica,
      applied: new Set(),
      pending: new Map(),
    };
  }

  #recordLocal(node: Node, change: LocalChange, writes: Write[]): void {
    const past = new Set(node.applied);
    node.applied.add(change.hash);
    this.bytes.set(change.hash, change.change);
    this.oracle.record({
      hash: change.hash,
      past,
      writes,
      label: `${node.name}#${change.seq} ${change.intent}`,
      replica: node.name,
    });
  }

  /** task.create of a fresh Task at replica r. */
  create(r: number, v: number): void {
    const node = this.nodes[r % this.nodes.length] as Node;
    const id = objectIdOf(this.#nextObject++);
    const title = POOL.title[v % POOL.title.length] as string;
    const intent: TaskIntent = {
      intent: "task.create",
      task: {
        id,
        type: "task",
        lifecycle: "active",
        created_by: principalRef(node.principal),
        title,
        status: "todo",
        priority: "normal",
        tags: {},
        assignees: {},
        extensions: {},
      },
    };
    const change = node.replica.apply(intent);
    if (change === null) throw new Error("task.create made no change");
    const put = (register: string, value: Json): Write => ({
      object: id,
      register,
      put: true,
      value,
    });
    this.#recordLocal(node, change, [
      put("lifecycle", "active"),
      put("title", title),
      put("status", "todo"),
      put("priority", "normal"),
    ]);
    this.objects.push({ id, created: change.hash });
    this.log.push(`${node.name}: create ${id} "${title}"`);
  }

  /** The intent that choice (k, v) means for object `id` at node, and its register writes. */
  #intent(
    node: Node,
    id: ObjectId,
    k: number,
    v: number,
  ): { intent: ReplicaIntent; writes: Write[] } {
    const pick = <T>(pool: readonly T[]): T => pool[v % pool.length] as T;
    const put = (register: string, value: Json): Write => ({
      object: id,
      register,
      put: true,
      value,
    });
    // A delete writes only when the register is present locally (an absent key has nothing to delete).
    const del = (register: string): Write[] =>
      this.oracle.present(node.applied, id, register)
        ? [{ object: id, register, put: false, value: null }]
        : [];
    const kinds = 17;
    switch (k % kinds) {
      case 0: {
        const title = pick(POOL.title);
        return { intent: { intent: "task.set_title", id, title }, writes: [put("title", title)] };
      }
      case 1: {
        const status = pick(POOL.status) as "todo";
        return {
          intent: { intent: "task.set_status", id, status },
          writes: [put("status", status)],
        };
      }
      case 2: {
        const date = pick(POOL.date);
        return {
          intent: { intent: "task.complete", id, completionDate: date },
          writes: [put("status", "done"), put("completion_date", date)],
        };
      }
      case 3:
        return {
          intent: { intent: "task.reopen", id },
          writes: [put("status", "todo"), ...del("completion_date")],
        };
      case 4:
        return {
          intent: { intent: "task.cancel", id },
          writes: [put("status", "cancelled"), ...del("completion_date")],
        };
      case 5: {
        const date = pick(POOL.date);
        return { intent: { intent: "task.set_due", id, date }, writes: [put("due", date)] };
      }
      case 6:
        return { intent: { intent: "task.clear_due", id }, writes: del("due") };
      case 7: {
        const date = pick(POOL.date);
        return {
          intent: { intent: "task.set_scheduled", id, date },
          writes: [put("scheduled", date)],
        };
      }
      case 8: {
        const priority = pick(POOL.priority) as "normal";
        return {
          intent: { intent: "task.set_priority", id, priority },
          writes: [put("priority", priority)],
        };
      }
      case 9: {
        const tag = pick(POOL.tag);
        return { intent: { intent: "task.add_tag", id, tag }, writes: [put(`tags/${tag}`, true)] };
      }
      case 10: {
        const tag = pick(POOL.tag);
        return { intent: { intent: "task.remove_tag", id, tag }, writes: del(`tags/${tag}`) };
      }
      case 11: {
        const assignee = pick(ASSIGNEES);
        return {
          intent: { intent: "task.add_assignee", id, assignee },
          writes: [put(`assignees/${assignee}`, true)],
        };
      }
      case 12: {
        const assignee = pick(ASSIGNEES);
        return {
          intent: { intent: "task.remove_assignee", id, assignee },
          writes: del(`assignees/${assignee}`),
        };
      }
      case 13:
        return { intent: { intent: "task.delete", id }, writes: [put("lifecycle", "deleted")] };
      case 14:
        return { intent: { intent: "task.restore", id }, writes: [put("lifecycle", "active")] };
      default: {
        // §69 task.resolve_field_conflict, on any scalar register.
        const field = SCALAR_FIELDS[(k >> 5) % SCALAR_FIELDS.length] as ScalarField;
        const pools: Record<ScalarField, readonly (string | null)[]> = {
          lifecycle: POOL.lifecycle,
          title: POOL.title,
          status: POOL.status,
          priority: POOL.priority,
          due: [...POOL.date, null],
          scheduled: [...POOL.date, null],
          completion_date: [...POOL.date, null],
        };
        const value = pick(pools[field]);
        return {
          intent: { intent: "task.resolve_field_conflict", id, field, value },
          writes: value === null ? del(field) : [put(field, value)],
        };
      }
    }
  }

  /** One semantic intent at replica r on one of the objects it knows. */
  op(r: number, o: number, k: number, v: number): void {
    const node = this.nodes[r % this.nodes.length] as Node;
    const known = this.objects.filter((x) => node.applied.has(x.created));
    if (known.length === 0) return;
    const { id } = known[o % known.length] as { id: string };
    const { intent, writes } = this.#intent(node, id as ObjectId, k, v);
    let change: LocalChange | null;
    try {
      change = node.replica.apply(intent);
    } catch (e) {
      throw new Error(
        `${node.name}: ${intent.intent} on ${id} was refused (${(e as Error).message}); ` +
          `every generated intent is profile-valid, so a merged object must stay writable`,
      );
    }
    const description = `${node.name}: ${JSON.stringify(intent)}`;
    if (change === null) {
      if (writes.length > 0)
        throw new Error(`${description} made no change, but the oracle expects writes`);
      this.log.push(`${description} -> no change`);
      return;
    }
    this.#recordLocal(node, change, writes);
    this.log.push(`${description} -> ${change.hash.slice(0, 8)}`);
  }

  /**
   * Deliver `hashes` to replica `to`, in the given order. A change whose
   * dependencies are missing waits; every delivery retries what waits.
   */
  deliver(to: number, hashes: readonly string[]): void {
    const node = this.nodes[to % this.nodes.length] as Node;
    for (const hash of hashes) {
      const bytes = this.bytes.get(hash) as Uint8Array;
      const result = node.replica.receiveChange(bytes);
      if (result.status === "applied") node.applied.add(hash);
      else if (result.status === "duplicate") {
        if (!node.applied.has(hash))
          throw new Error(`${node.name}: ${hash} duplicate but never applied`);
      } else node.pending.set(hash, bytes);
      this.#drain(node);
    }
  }

  #drain(node: Node): void {
    for (let progress = true; progress; ) {
      progress = false;
      for (const [hash, bytes] of node.pending) {
        const result = node.replica.receiveChange(bytes);
        if (result.status === "missing_dependencies") continue;
        node.pending.delete(hash);
        node.applied.add(hash);
        progress = true;
      }
    }
  }

  /** Send part of what `from` has and `to` lacks, shuffled, maybe with duplicates. */
  sync(from: number, to: number, take: number, seed: number, dup: boolean): void {
    const [a, b] = [from % this.nodes.length, to % this.nodes.length];
    if (a === b) return;
    const source = this.nodes[a] as Node;
    const target = this.nodes[b] as Node;
    const random = prng(seed);
    const missing = shuffled(
      [...source.applied].filter((h) => !target.applied.has(h)),
      random,
    );
    const batch = missing.slice(0, 1 + (take % Math.max(1, missing.length)));
    if (dup && batch.length > 0) batch.push(...batch.slice(0, 1 + (take % batch.length)));
    if (dup) batch.push(...shuffled([...target.applied], random).slice(0, 2));
    this.deliver(b, batch);
    this.log.push(
      `sync ${source.name} -> ${target.name}: ${batch.length} delivered` +
        `${dup ? " (with duplicates)" : ""}, ${target.pending.size} waiting`,
    );
  }

  /** Every change to every replica, each in its own random order, with duplicates. */
  converge(seed: number): void {
    const random = prng(seed);
    const all = [...this.bytes.keys()];
    this.nodes.forEach((_, i) => {
      const order = shuffled([...all, ...all.slice(0, Math.ceil(all.length / 3))], random);
      this.deliver(i, order);
    });
    this.log.push(`converge: every change to every replica (seed ${seed})`);
  }

  run(program: Program): void {
    for (const step of program.steps) {
      if (step.t === "op") this.op(step.r, step.o, step.k, step.v);
      else if (step.t === "create") this.create(step.r, step.v);
      else this.sync(step.from, step.to, step.take, step.seed, step.dup);
    }
  }

  /** A failure message with the context LFCP-037 asks for. */
  report(what: string, details: readonly string[]): string {
    return [
      what,
      ...details.map((d) => `  ${d}`),
      `replicas: ${this.nodes.map((n) => `${n.name}=${toHex(n.replica.actorId).slice(0, 12)}`).join(", ")}`,
      `objects: ${this.objects.map((o) => o.id).join(", ")}`,
      "operations:",
      ...this.log.map((l) => `  ${l}`),
    ].join("\n");
  }
}

// ---------------------------------------------------------------- invariants

/** Check every LFCP-037 invariant on a converged world; returns failure messages. */
export function checkConverged(world: World, fault?: Fault): string[] {
  const failures: string[] = [];
  const all = new Set(world.bytes.keys());
  const expected = expectedObservation(world.oracle.expected(all));
  const first = world.nodes[0] as Node;
  for (const node of world.nodes) {
    if (node.pending.size > 0)
      failures.push(`${node.name}: ${node.pending.size} changes never applied`);
    if (node.applied.size !== all.size)
      failures.push(`${node.name}: applied ${node.applied.size} of ${all.size} changes`);
    // (a) the same logical state and conflict sets everywhere, and the oracle's.
    let observed = observe(node.replica);
    if (fault !== undefined) observed = fault(observed, world);
    for (const d of differences(observed, expected)) failures.push(`${node.name} vs oracle: ${d}`);
    if (canonical(node.replica.root()) !== canonical(first.replica.root()))
      failures.push(`${node.name}: logical state differs from ${first.name}`);
    if (canonical(node.replica.conflicts()) !== canonical(first.replica.conflicts()))
      failures.push(
        `${node.name}: conflicts ${JSON.stringify(node.replica.conflicts())} differ from ` +
          `${first.name}'s ${JSON.stringify(first.replica.conflicts())}`,
      );
    // (b) the merged state is profile-valid: no conflict turns into Text or invalid data.
    const validation = node.replica.validate();
    if (!validation.valid || validation.collisions.length > 0)
      failures.push(
        `${node.name}: validate() ${JSON.stringify(validation.problems)} collisions ${JSON.stringify(validation.collisions)}`,
      );
    // (d) re-applying every seen change is a no-op.
    const heads = node.replica.heads();
    const count = node.replica.changes().length;
    for (const bytes of world.bytes.values()) {
      const result = node.replica.receiveChange(bytes);
      if (result.status !== "duplicate") {
        failures.push(`${node.name}: re-applying ${checkChange(bytes).hash} was ${result.status}`);
        break;
      }
    }
    if (node.replica.heads().join() !== heads.join() || node.replica.changes().length !== count)
      failures.push(`${node.name}: re-applying seen changes changed the history`);
  }
  // (c) after the merge, a further intent succeeds on every object, on every replica.
  for (const node of world.nodes) {
    const copy = SharedObjectsReplica.fromSave(node.replica.save(), {
      resource: RESOURCE,
      principal: node.principal,
      minSeq: node.replica.actorSeq,
    });
    for (const { id } of world.objects) {
      const objectId = id as ObjectId;
      for (const intent of [
        { intent: "task.set_title", id: objectId, title: "After merge" },
        { intent: "task.set_status", id: objectId, status: "in_progress" },
        { intent: "task.add_tag", id: objectId, tag: "merged" },
      ] as const) {
        try {
          if (copy.apply(intent) === null)
            failures.push(`${node.name}: ${intent.intent} on ${id} made no change`);
        } catch (e) {
          failures.push(`${node.name}: ${intent.intent} on ${id} refused: ${(e as Error).message}`);
        }
      }
    }
    const after = copy.validate();
    if (!after.valid)
      failures.push(
        `${node.name}: invalid after further intents: ${JSON.stringify(after.problems)}`,
      );
  }
  return failures;
}

/** Replicate the logical state of `world` from a subset of its changes (G-EP7 property). */
export function rebuildCheck(world: World, exclude: ReadonlySet<string>, seed: number): string[] {
  const node = world.nodes[0] as Node;
  // Excluding a change excludes everything that saw it.
  const removed = new Set<string>();
  for (const [hash, change] of world.oracle.changes)
    if (exclude.has(hash) || [...exclude].some((x) => change.past.has(x))) removed.add(hash);
  const kept = [...world.bytes.keys()].filter((h) => !removed.has(h));
  const rebuilt = node.replica.rebuildWithout(removed).replica;
  const fresh = SharedObjectsReplica.empty({
    resource: RESOURCE,
    principal: PRINCIPALS[4] as PrincipalId,
  });
  const random = prng(seed);
  const waiting = shuffled(
    kept.map((h) => world.bytes.get(h) as Uint8Array),
    random,
  );
  for (let progress = true; progress && waiting.length > 0; ) {
    progress = false;
    for (let i = waiting.length - 1; i >= 0; i--) {
      if (fresh.receiveChange(waiting[i] as Uint8Array).status !== "missing_dependencies") {
        waiting.splice(i, 1);
        progress = true;
      }
    }
  }
  const failures: string[] = [];
  if (waiting.length > 0)
    failures.push(`fresh replica: ${waiting.length} kept changes never applied`);
  const expected = expectedObservation(world.oracle.expected(new Set(kept)));
  for (const d of differences(observe(rebuilt), expected)) failures.push(`rebuilt vs oracle: ${d}`);
  if (canonical(rebuilt.root()) !== canonical(fresh.root()))
    failures.push("rebuilt state differs from a fresh replica of the kept set");
  if (canonical(rebuilt.conflicts()) !== canonical(fresh.conflicts()))
    failures.push("rebuilt conflicts differ from a fresh replica of the kept set");
  return failures;
}

// A§3.5 (E-030): what admission and the replica keep up to date, change by change, equals what
// the full computation gives on the same history: validation reused on the shadow's unchanged
// objects (ScReader.memo) against validation read afresh, on random histories of C's entries with
// concurrent writers and rollbacks, and on the recorded units of the bridge's synthetic year.

import * as A from "@automerge/automerge";
import { fromBase64url, fromHex, principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange } from "../src/admission/framing.js";
import {
  checkServiceControlUnit,
  entryDiagnostics,
  ScReader,
  ServiceControlAdmission,
  type ServiceControlContainer,
  ServiceControlReplica,
  type ServiceControlSignerClass,
} from "../src/service-control/index.js";
import { isObject, type ScBackend } from "../src/service-control/reader.js";
import { ShadowDoc } from "../src/service-control/shadow.js";
import { SERVICE_CONTROL_ROOT_KEYS, WHOLE_CONTAINERS } from "../src/service-control/values.js";
import {
  approval,
  B,
  C,
  type Doc,
  edit,
  initial,
  last,
  personal,
  principalRef,
  put,
  request,
  resource,
  root,
  T0,
  uid,
  X,
} from "./support/service-control.js";
import bridgeUnits from "./support/service-control-bridge-units.json" with { type: "json" };
import { syntheticYear } from "./support/service-control-year.js";

function random(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
}

/** The shadow without versions: every reading through it is computed afresh. */
const afresh = (b: ShadowDoc): ScBackend => ({
  getWithType: (obj, key) => b.getWithType(obj, key),
  getAll: (obj, key) => b.getAll(obj, key),
  keys: (obj) => b.keys(obj),
  length: (obj) => b.length(obj),
});

/** §5 and §4 Sizes of every value of every entry of C (each concurrent value), as read through `b`. */
function diagnostics(b: ScBackend): unknown[] {
  const r = new ScReader(b);
  const out: unknown[] = [];
  for (const top of r.keys("_root")) {
    const v = r.get("_root", top);
    if (WHOLE_CONTAINERS.has(top) || top === "meta" || v?.[0] !== "map") {
      out.push([top, [...entryDiagnostics(r, top, undefined, v, C)].sort(), r.size(v)]);
      continue;
    }
    for (const key of r.keys(String(v[1])))
      for (const e of r.all(String(v[1]), key))
        out.push([top, key, [...entryDiagnostics(r, top, key, e, C)].sort(), r.size(e)]);
  }
  return out;
}

let invalid = 0;

function expectSameDiagnostics(shadow: ShadowDoc, engine?: ScBackend): void {
  const memo = diagnostics(shadow);
  invalid += memo.filter((d) =>
    (d as unknown[]).some((x) => Array.isArray(x) && x.length > 0),
  ).length;
  expect(memo).toEqual(diagnostics(afresh(shadow)));
  if (engine !== undefined) expect(memo).toEqual(diagnostics(engine));
}

const BINDING = {
  state: "on",
  generation: 1,
  list: "Inbox",
  filter: "all",
  pending: { toApple: 0, toLfcp: 0 },
  refused: 0,
  unconfirmed: 0,
  preview: { id: "p", planHash: "h", filter: "all", list: "Inbox", items: ["a"], counts: { a: 1 } },
};
const QUESTION = {
  binding: X,
  generation: 1,
  kind: "mass-delete",
  anomalyId: "a",
  snapshotHash: "s",
  items: ["x"],
  counts: { deleted: 3 },
  options: ["apply"],
  at: T0,
};

/** One random write below an entry of C: fields set, deleted, of a wrong type, lists and counts. */
function randomEdit(d: Doc, rnd: () => number): void {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
  const value = () => pick<unknown>([1, 2, "on", "x".repeat(1 + Math.floor(rnd() * 90)), T0, true]);
  const key = pick([X, C, "bad-key"]);
  const q = uid(1 + Math.floor(rnd() * 2));
  switch (Math.floor(rnd() * 8)) {
    case 0:
      put(d.bindings, key, BINDING);
      break;
    case 1:
      if (d.bindings[key] !== undefined) put(d.bindings[key], pick(Object.keys(BINDING)), value());
      break;
    case 2:
      if (d.bindings[key]?.preview?.items !== undefined)
        put(d.bindings[key].preview.items, d.bindings[key].preview.items.length, value());
      break;
    case 3:
      if (d.bindings[key]?.preview?.counts !== undefined)
        put(d.bindings[key].preview.counts, pick(["a", "b", "c"]), value());
      break;
    case 4:
      if (d.bindings[key]?.preview !== undefined)
        delete d.bindings[key].preview[pick(["id", "items"])];
      break;
    case 5:
      put(d.questions, q, QUESTION);
      break;
    case 6:
      if (d.questions[q] !== undefined)
        put(d.questions[q], "resolved", { answerId: q, choice: "apply", at: T0 });
      break;
    default:
      put(d, "status", { state: "running", since: T0, heartbeatAt: value() });
  }
}

describe("validation reused on the shadow's unchanged objects equals validation afresh", () => {
  it("40 random histories of C's entries by three writers, with rollbacks", () => {
    let undone = 0;
    for (let seed = 1; seed <= 40; seed++) {
      const rnd = random(seed);
      const base = initial(root);
      const signers = [root, personal, B];
      const docs = signers.map(() => A.clone(base));
      const history = [last(base)];
      const shadow = new ShadowDoc(8);
      shadow.applyChecked(checkChange(last(base)));
      let engine = A.clone(base);
      for (let step = 0; step < 40; step++) {
        const k = Math.floor(rnd() * docs.length);
        if (rnd() < 0.3)
          docs[k] = A.merge(
            docs[k] as A.Doc<Doc>,
            A.clone(docs[Math.floor(rnd() * docs.length)] as A.Doc<Doc>),
          );
        const edited = edit(docs[k] as A.Doc<Doc>, signers[k] as never, (d) => {
          for (let n = 1 + Math.floor(rnd() * 3); n > 0; n--) randomEdit(d, rnd);
        });
        if (A.getHeads(edited).join() === A.getHeads(docs[k] as A.Doc<Doc>).join()) continue;
        docs[k] = edited;
        const bytes = last(edited);
        shadow.applyChecked(checkChange(bytes));
        history.push(bytes);
        [engine] = A.applyChanges(engine, [bytes]);
        expectSameDiagnostics(shadow, A.getBackend(engine));
        if (rnd() < 0.3) {
          const back = 1 + Math.floor(rnd() * shadow.depth);
          const redo = Array.from({ length: back }, () => shadow.undo()).reverse();
          expectSameDiagnostics(shadow);
          for (const c of redo) if (c !== undefined) shadow.apply(c);
          expectSameDiagnostics(shadow, A.getBackend(engine));
          undone += back;
        }
      }
    }
    expect(undone).toBeGreaterThan(40);
    expect(invalid).toBeGreaterThan(40);
  }, 120_000);

  it("the recorded units of the bridge's synthetic year, refused ones rolled back", () => {
    const fixture = bridgeUnits as {
      resource: string;
      root: string;
      genesisSigner: string;
      units: { signer: string; seq: number; cls: ServiceControlSignerClass; bytes: string }[];
    };
    const options = {
      resource: resourceId(fromHex(fixture.resource)),
      root: principalId(fromHex(fixture.root)),
      genesisSigner: principalId(fromHex(fixture.genesisSigner)),
    };
    const admission = new ServiceControlAdmission(options);
    const shadow = new ShadowDoc(16);
    const rnd = random(11);
    let refused = 0;
    for (const unit of fixture.units) {
      const change = checkChange(fromBase64url(unit.bytes));
      const writer = {
        signer: principalId(fromHex(unit.signer)),
        actorSeq: unit.seq,
        signerClass: unit.cls,
      };
      shadow.applyChecked(change);
      expectSameDiagnostics(shadow);
      try {
        checkServiceControlUnit(change, writer, options);
        admission.accept(change, writer);
      } catch {
        shadow.undo();
        refused++;
        expectSameDiagnostics(shadow);
      }
      if (rnd() < 0.2) {
        const back = 1 + Math.floor(rnd() * shadow.depth);
        const redo = Array.from({ length: back }, () => shadow.undo()).reverse();
        expectSameDiagnostics(shadow);
        for (const c of redo) if (c !== undefined) shadow.apply(c);
      }
    }
    expectSameDiagnostics(shadow, A.getBackend(admission.document));
    expect(fixture.units.length - refused).toBeGreaterThan(100);
  }, 120_000);
});

/** The engine's document of the replica's admitted history. */
const documentOf = (replica: ServiceControlReplica) => A.load<unknown>(replica.save());

/** creatorsOf as it was computed before E-030: every admitted change decoded and searched. */
function creatorsFull(replica: ServiceControlReplica, container: string, key: string) {
  const reader = new ScReader(A.getBackend(documentOf(replica)));
  const map = reader.map("_root", container);
  if (map === undefined) return [];
  const made = reader
    .all(map, key)
    .filter(isObject)
    .map((v) => {
      const [counter, actor] = String(v[1]).split("@");
      return { counter: Number(counter), actor };
    });
  const out: unknown[] = [];
  for (const bytes of replica.changes()) {
    const change = A.decodeChange(bytes);
    const end = change.startOp + change.ops.length;
    if (
      made.some((m) => m.actor === change.actor && m.counter >= change.startOp && m.counter < end)
    )
      out.push({ hash: change.hash, ...replica.authorOf(change.hash) });
  }
  return out;
}

const byHash = (xs: readonly unknown[]) =>
  [...xs].sort((a, b) => ((a as { hash: string }).hash < (b as { hash: string }).hash ? -1 : 1));

/** Every entry of every container of C: creatorsOf equals the full search. */
function expectSameCreators(replica: ServiceControlReplica): number {
  const reader = new ScReader(A.getBackend(documentOf(replica)));
  let entries = 0;
  for (const container of SERVICE_CONTROL_ROOT_KEYS.slice(2)) {
    const map = reader.map("_root", container);
    for (const key of map === undefined ? [] : [...reader.keys(map), "absent"]) {
      const c = container as ServiceControlContainer;
      expect(byHash(replica.creatorsOf(c, key))).toEqual(byHash(creatorsFull(replica, c, key)));
      entries++;
    }
  }
  return entries;
}

/** requestHistory as it was computed before E-030: the history decoded, each value validated at its creator. */
function requestHistoryFull(replica: ServiceControlReplica) {
  const reader = new ScReader(A.getBackend(documentOf(replica)));
  const container = reader.map("_root", "requests");
  if (container === undefined) return [];
  const made = new Map<string, unknown[]>();
  for (const bytes of replica.changes()) {
    const change = A.decodeChange(bytes);
    const author = replica.authorOf(change.hash);
    for (const op of change.ops as { action: string; obj: string; key?: unknown }[])
      if (op.obj === container && op.action.startsWith("make") && typeof op.key === "string")
        made.set(op.key, [...(made.get(op.key) ?? []), { hash: change.hash, ...author }]);
  }
  const now = replica.validate().requests;
  return [...made]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .flatMap(([rid, creators]) => {
      const creator = creators[0] as { hash: string };
      const request = replica.validate([creator.hash]).requests[rid];
      if (creators.length !== 1 || request === undefined) return [];
      return [{ rid, request, present: Object.hasOwn(now, rid), creators }];
    });
}

let conflicts = 0;
let deleted = 0;

function expectSameRequestHistory(replica: ServiceControlReplica): void {
  const history = replica.requestHistory();
  expect(history).toEqual(requestHistoryFull(replica));
  deleted += history.filter((r) => !r.present).length;
  const reader = new ScReader(A.getBackend(documentOf(replica)));
  const requests = reader.map("_root", "requests") as string;
  for (const rid of reader.keys(requests)) if (reader.all(requests, rid).length > 1) conflicts++;
}

const options = { resource, root, genesisSigner: root };
const SIGNERS = [
  [root, "root"],
  [personal, "personal"],
  [B, "service-device"],
] as const;

/**
 * A random history of C through a replica: the root and the personal device create requests
 * (valid, invalid, the same rid concurrently) and answers, the service writes events, deletes
 * requests and entries, and writes its bindings; each writer merges the others' views at random,
 * and a change the replica refuses is dropped from its writer's view.
 */
/** A request in `d` whose event is final, as the service deletes it (§3). */
const settled = (d: Doc) =>
  Object.keys(d.requests).find((rid) =>
    ["applied", "rejected"].includes(String(d.events[rid]?.state)),
  );

function* randomReplica(seed: number, steps: number) {
  const rnd = random(seed);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
  const init = initial();
  const base = edit(init, personal, (d) => put(d.approvals, principalRef(B), approval(B)));
  const replica = ServiceControlReplica.empty(options);
  replica.receiveChanges([
    { bytes: last(init), signer: root, signerClass: "root", actorSeq: 1 },
    { bytes: last(base), signer: personal, signerClass: "personal", actorSeq: 1 },
  ]);
  const docs = SIGNERS.map(() => A.clone(base));
  for (let step = 0; step < steps; step++) {
    const k = Math.floor(rnd() * docs.length);
    const [signer, signerClass] = SIGNERS[k] as (typeof SIGNERS)[number];
    if (rnd() < 0.4) docs[k] = A.merge(docs[k] as A.Doc<Doc>, A.clone(pick(docs)));
    const rid = uid(1 + Math.floor(rnd() * 6));
    const edited = edit(docs[k] as A.Doc<Doc>, signer, (d) => {
      const op = Math.floor(rnd() * 6);
      if (signerClass !== "service-device") {
        if (op < 3) put(d.requests, rid, request(pick(["check", "check", "nope"])));
        else if (op < 4) put(d.requests, rid, { op: "check" });
        else put(d.answers, rid, { qid: rid, snapshotHash: "s", choice: "apply", at: T0 });
      } else if (op < 2 && settled(d) !== undefined) delete d.requests[settled(d) as string];
      else if (op < 2)
        put(d.events, rid, { state: pick(["received", "applied", "rejected", "applied"]), at: T0 });
      else if (op < 4) delete d[pick(["requests", "requests", "events", "answers"])][rid];
      else put(d.bindings, pick([X, C]), BINDING);
    });
    if (A.getHeads(edited).join() === A.getHeads(docs[k] as A.Doc<Doc>).join()) continue;
    const r = replica.receiveChanges([{ bytes: last(edited), signer, signerClass, actorSeq: 2 }]);
    if (r.admitted.length > 0) docs[k] = edited;
    yield replica;
  }
}

describe("the replica's indexes equal the full search of the admitted history", () => {
  it("creatorsOf on 8 random histories of requests, events, answers and bindings", () => {
    let entries = 0;
    for (let seed = 1; seed <= 8; seed++)
      for (const replica of randomReplica(seed, 40)) entries += expectSameCreators(replica);
    expect(entries).toBeGreaterThan(600);
  }, 120_000);

  it("requestHistory on 8 random histories, conflicted and deleted requests included", () => {
    for (let seed = 1; seed <= 8; seed++)
      for (const replica of randomReplica(seed, 40)) expectSameRequestHistory(replica);
    expect(conflicts).toBeGreaterThan(0);
    expect(deleted).toBeGreaterThan(0);
  }, 120_000);

  it("creatorsOf on a synthetic week with refused changes, in one batch and unit by unit", () => {
    const year = syntheticYear({ days: 7, refusals: true });
    expectSameCreators(ServiceControlReplica.fromChanges(year.units, year.options).replica);
    const replica = ServiceControlReplica.empty(year.options);
    for (const [i, unit] of year.units.entries()) {
      replica.receiveChanges([unit]);
      if (i % 200 === 0) expectSameCreators(replica);
    }
    expect(expectSameCreators(replica)).toBeGreaterThan(20);
    expectSameRequestHistory(replica);
  }, 120_000);

  it("creatorsOf and requestHistory on the recorded units of the bridge's synthetic year", () => {
    const fixture = bridgeUnits as {
      resource: string;
      root: string;
      genesisSigner: string;
      units: { signer: string; seq: number; cls: ServiceControlSignerClass; bytes: string }[];
    };
    const replica = ServiceControlReplica.empty({
      resource: resourceId(fromHex(fixture.resource)),
      root: principalId(fromHex(fixture.root)),
      genesisSigner: principalId(fromHex(fixture.genesisSigner)),
    });
    for (const [i, unit] of fixture.units.entries()) {
      replica.receiveChanges([
        {
          bytes: fromBase64url(unit.bytes),
          signer: principalId(fromHex(unit.signer)),
          signerClass: unit.cls,
          actorSeq: unit.seq,
        },
      ]);
      if (i % 50 === 0) {
        expectSameCreators(replica);
        expectSameRequestHistory(replica);
      }
    }
    expect(expectSameCreators(replica)).toBeGreaterThan(20);
    // The recording holds the service's writes only: no change of it makes a request.
    expectSameRequestHistory(replica);
  }, 120_000);

  it("a request taken from requestHistory cannot change what later calls return", () => {
    const init = initial();
    const made = edit(init, root, (d) =>
      put(d.requests, uid(1), request("check", { args: { nested: { value: 1 } } })),
    );
    const replica = ServiceControlReplica.empty(options);
    replica.receiveChanges([
      { bytes: last(init), signer: root, signerClass: "root", actorSeq: 1 },
      { bytes: last(made), signer: root, signerClass: "root", actorSeq: 2 },
    ]);
    type Nested = { nested: { value: number } };
    const argsOf = (r: ServiceControlReplica) => r.requestHistory()[0]?.request.args as Nested;
    const { nested } = argsOf(replica);
    expect(() => {
      nested.value = 999;
    }).toThrow(TypeError);
    expect(argsOf(replica).nested.value).toBe(1);
    expectSameRequestHistory(replica);
  });

  it("a request with byte values and timestamps is admitted and handed out as fresh copies", () => {
    const init = initial();
    // put() writes objects as maps: the bytes and the timestamp are set as Automerge scalars.
    const made = edit(init, root, (d) => {
      put(d.requests, uid(1), request("check", { extra: {} }));
      const r = d.requests[uid(1)];
      r.args.payload = new Uint8Array([1, 2, 3]);
      r.args.when = new Date(0);
      r.extra.blob = new Uint8Array([4]);
    });
    const replica = ServiceControlReplica.empty(options);
    const r = replica.receiveChanges([
      { bytes: last(init), signer: root, signerClass: "root", actorSeq: 1 },
      { bytes: last(made), signer: root, signerClass: "root", actorSeq: 2 },
    ]);
    expect(r.admitted).toHaveLength(2);
    expectSameRequestHistory(replica);
    type Bytes = { payload: Uint8Array; when: Date };
    const argsOf = (x: ServiceControlReplica) => x.requestHistory()[0]?.request.args as Bytes;
    const { payload, when } = argsOf(replica);
    payload[0] = 9;
    when.setTime(1);
    expect(argsOf(replica).payload).toEqual(new Uint8Array([1, 2, 3]));
    expect(argsOf(replica).when.getTime()).toBe(0);
    expectSameRequestHistory(replica);
  });
});

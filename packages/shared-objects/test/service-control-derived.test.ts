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
  type ServiceControlSignerClass,
} from "../src/service-control/index.js";
import type { ScBackend } from "../src/service-control/reader.js";
import { ShadowDoc } from "../src/service-control/shadow.js";
import { WHOLE_CONTAINERS } from "../src/service-control/values.js";
import {
  B,
  C,
  type Doc,
  edit,
  initial,
  last,
  personal,
  put,
  root,
  T0,
  uid,
  X,
} from "./support/service-control.js";
import bridgeUnits from "./support/service-control-bridge-units.json" with { type: "json" };

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

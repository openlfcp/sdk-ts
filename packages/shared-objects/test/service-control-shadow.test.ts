// A.§3.5 (E-030): the shadow model of C's visible state equals a full replay
// of the history it was given after every step: random histories of three
// writers with concurrent map, list, text and counter edits, and a recorded
// run of the bridge's synthetic year through C's admission, both with
// changes rolled back from the undo log and applied again, and with
// refused changes applied and rolled back.

import * as A from "@automerge/automerge";
import { fromBase64url, fromHex, principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange } from "../src/admission/framing.js";
import {
  checkServiceControlUnit,
  ScReader,
  ServiceControlAdmission,
  type ServiceControlSignerClass,
} from "../src/service-control/index.js";
import type { ScBackend } from "../src/service-control/reader.js";
import { ShadowDoc, ShadowUnsupported } from "../src/service-control/shadow.js";
import type { Doc } from "./support/service-control.js";
import bridgeUnits from "./support/service-control-bridge-units.json" with { type: "json" };

const SEEDS = 80;
const STEPS = 50;

function random(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
}

const replay = (changes: readonly Uint8Array[]) =>
  A.getBackend(A.applyChanges(A.init<unknown>(), [...changes])[0]);

const OBJECTS = new Set(["map", "list", "text"]);

/** Every visible key or index of every reachable object, with all concurrent values and their IDs. */
function dump(b: ScBackend, obj = "_root", kind = "map"): unknown {
  const slot = (key: string | number) => ({
    get: b.getWithType(obj, key),
    all: (b.getAll(obj, key) as unknown[][]).map((v) =>
      OBJECTS.has(String(v[0])) ? [...v, dump(b, String(v[1]), String(v[0]))] : v,
    ),
  });
  if (kind === "map") return { length: b.length(obj), keys: b.keys(obj).map((k) => [k, slot(k)]) };
  return Array.from({ length: b.length(obj) }, (_, i) => slot(i));
}

/** The shadow and the engine agree on the dump and on ScReader's projection and §4 size. */
function expectSame(shadow: ShadowDoc, engine: ScBackend): void {
  expect(dump(shadow)).toEqual(dump(engine));
  const [s, e] = [new ScReader(shadow), new ScReader(engine)];
  const root = ["map", "_root"] as const;
  expect(s.plain(root)).toEqual(e.plain(root));
  expect(s.size(root)).toBe(e.size(root));
}

const KEYS = ["a", "b", "c", "é", "\u{1F600}", "�", "zz"];

/** One random edit of `d`: maps, nested maps, conflicts, counters, lists and text. */
// biome-ignore lint/suspicious/noExplicitAny: random edits of an untyped document
function randomEdit(d: any, rnd: () => number): void {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
  const scalar = () =>
    pick([
      () => new A.ImmutableString(`s${Math.floor(rnd() * 9)}`),
      () => Math.floor(rnd() * 100) - 50,
      () => rnd() * 10,
      () => rnd() < 0.5,
      () => null,
      () => new Date(Math.floor(rnd() * 1e12)),
      () => Uint8Array.of(Math.floor(rnd() * 256)),
      () => new A.Counter(Math.floor(rnd() * 5)),
    ])();
  const target = d.m.n !== null && typeof d.m.n === "object" && rnd() < 0.3 ? d.m.n : d.m;
  const key = pick(KEYS);
  switch (Math.floor(rnd() * 9)) {
    case 0:
    case 1:
      target[key] = scalar();
      break;
    case 2:
      if (key in target) delete target[key];
      break;
    case 3:
      d.m.n = { [key]: scalar() };
      break;
    case 4:
      if (target[key] instanceof A.Counter) target[key].increment(Math.floor(rnd() * 7) - 3);
      else target[key] = new A.Counter(1);
      break;
    case 5:
      d.l.insertAt(Math.floor(rnd() * (d.l.length + 1)), rnd() < 0.2 ? { x: scalar() } : scalar());
      break;
    case 6:
      if (d.l.length > 0) d.l.deleteAt(Math.floor(rnd() * d.l.length));
      break;
    case 7:
      if (d.l.length > 0) d.l[Math.floor(rnd() * d.l.length)] = scalar();
      break;
    default: {
      const at = Math.floor(rnd() * (d.t.length + 1));
      A.splice(d, ["t"], at, rnd() < 0.3 ? Math.min(2, d.t.length - at) : 0, pick(["x", "yz", ""]));
    }
  }
}

describe("the shadow of C's visible state equals a full replay", () => {
  it(`${SEEDS} random histories of three writers, with rollbacks and refused changes`, () => {
    let undone = 0;
    let refused = 0;
    let concurrent = 0;
    for (let seed = 1; seed <= SEEDS; seed++) {
      const rnd = random(seed);
      const actors = ["aa01", "bb02", "cc03"];
      const base = A.change(A.init<Doc>({ actor: actors[0] as string }), (d) => {
        Object.assign(d, { m: {}, l: [], t: "" });
      });
      let docs = actors.map((a) => A.clone(base, { actor: a }));
      const history: Uint8Array[] = [A.getLastLocalChange(base) as Uint8Array];
      const shadow = new ShadowDoc(8);
      shadow.applyChecked(checkChange(history[0] as Uint8Array));
      let engine = A.clone(base);
      for (let step = 0; step < STEPS; step++) {
        const k = Math.floor(rnd() * docs.length);
        const other = docs[Math.floor(rnd() * docs.length)] as A.Doc<Doc>;
        if (rnd() < 0.3) docs[k] = A.merge(docs[k] as A.Doc<Doc>, A.clone(other));
        const edited = A.change(
          A.clone(docs[k] as A.Doc<Doc>, { actor: actors[k] as string }),
          (d) => {
            for (let n = 1 + Math.floor(rnd() * 3); n > 0; n--) randomEdit(d, rnd);
          },
        );
        // An edit that changed nothing makes no change (the last local one is an older change).
        if (A.getHeads(edited).join() === A.getHeads(docs[k] as A.Doc<Doc>).join()) continue;
        const bytes = A.getLastLocalChange(edited) as Uint8Array;
        const change = checkChange(bytes);
        if (rnd() < 0.1) {
          // A refused change: applied, compared, then rolled back exactly.
          shadow.applyChecked(change);
          expectSame(shadow, replay([...history, bytes]));
          shadow.undo();
          expectSame(shadow, replay(history));
          refused++;
          continue;
        }
        docs[k] = edited;
        if (change.deps.join() !== [...A.getHeads(engine)].sort().join()) concurrent++;
        shadow.applyChecked(change);
        history.push(bytes);
        [engine] = A.applyChanges(engine, [bytes]);
        expectSame(shadow, replay(history));
        if (rnd() < 0.2) {
          // Back to a fork point and forward again, as a concurrent change is judged.
          const back = 1 + Math.floor(rnd() * shadow.depth);
          const redo = Array.from({ length: back }, () => shadow.undo()).reverse();
          expectSame(shadow, replay(history.slice(0, history.length - back)));
          for (const c of redo) if (c !== undefined) shadow.apply(c);
          expectSame(shadow, replay(history));
          undone += back;
        }
      }
      docs = [];
    }
    expect(undone).toBeGreaterThan(SEEDS);
    expect(refused).toBeGreaterThan(SEEDS / 4);
    expect(concurrent).toBeGreaterThan(SEEDS);
  }, 120_000);

  it("a recorded run of the bridge's synthetic year through C's admission", () => {
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
    const rnd = random(7);
    const accepted: Uint8Array[] = [];
    let refusals = 0;
    let concurrent = 0;
    for (const unit of fixture.units) {
      const change = checkChange(fromBase64url(unit.bytes));
      const writer = {
        signer: principalId(fromHex(unit.signer)),
        actorSeq: unit.seq,
        signerClass: unit.cls,
      };
      if (change.deps.join() !== [...A.getHeads(admission.document)].sort().join()) concurrent++;
      shadow.applyChecked(change);
      try {
        checkServiceControlUnit(change, writer, options);
        admission.accept(change, writer);
        accepted.push(change.bytes);
      } catch {
        shadow.undo();
        refusals++;
      }
      expectSame(shadow, A.getBackend(admission.document));
      expectSame(shadow, replay(accepted));
      if (rnd() < 0.25) {
        const back = 1 + Math.floor(rnd() * shadow.depth);
        const redo = Array.from({ length: back }, () => shadow.undo()).reverse();
        expectSame(shadow, replay(accepted.slice(0, accepted.length - back)));
        for (const c of redo) if (c !== undefined) shadow.apply(c);
        expectSame(shadow, replay(accepted));
      }
    }
    expect(accepted.length).toBe(fixture.units.length - refusals);
    expect(accepted.length).toBeGreaterThan(100);
    expect(concurrent).toBeGreaterThan(0);
  }, 120_000);
});

describe("the shadow's limits", () => {
  it("applies an unsupported change not at all, and reads at explicit heads not at all", () => {
    const doc = A.change(A.init<Doc>({ actor: "aa01" }), (d) => {
      Object.assign(d, { m: { a: 1 } });
    });
    const shadow = new ShadowDoc();
    shadow.applyChecked(checkChange(A.getLastLocalChange(doc) as Uint8Array));
    const before = dump(shadow);
    const marked = A.change(A.clone(doc), (d) => {
      d.m.a = 2;
      d.t = "hello";
      A.mark(d, ["t"], { start: 0, end: 2, expand: "none" }, "bold", true);
    });
    const change = checkChange(A.getLastLocalChange(marked) as Uint8Array);
    expect(() => shadow.applyChecked(change)).toThrow(ShadowUnsupported);
    expect(dump(shadow)).toEqual(before);
    expect(shadow.depth).toBe(1);
    expect(() => shadow.getWithType("_root", "m", [])).toThrow(ShadowUnsupported);
  });

  it("keeps at most `window` changes to roll back", () => {
    let doc = A.init<{ n?: number }>({ actor: "aa01" });
    const shadow = new ShadowDoc(3);
    for (let i = 0; i < 5; i++) {
      doc = A.change(doc, (d) => {
        d.n = i;
      });
      shadow.applyChecked(checkChange(A.getLastLocalChange(doc) as Uint8Array));
    }
    expect(shadow.depth).toBe(3);
    for (let i = 0; i < 3; i++) expect(shadow.undo()).toBeDefined();
    expect(shadow.undo()).toBeUndefined();
    expect(shadow.getWithType("_root", "n")).toEqual(["int", 1]);
  });
});

// A.§3.5 (E-030): admission of C on the shadow model decides every change as the engine path
// does: the same class, or the same refusal and diagnostic, for the same change streams. The
// streams are bridge-style synthetic histories with refused changes mixed in, delivered in the
// order they were written and in random causal orders (concurrent changes judged after the ones
// they miss), and the recorded units of the bridge's synthetic year.

import * as A from "@automerge/automerge";
import { fromBase64url, fromHex, principalId, resourceId } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { type CheckedChange, checkChange } from "../src/admission/framing.js";
import {
  checkServiceControlUnit,
  ServiceControlAdmission,
  type ServiceControlOptions,
  ServiceControlReplica,
  type ServiceControlSignerClass,
} from "../src/service-control/index.js";
import bridgeUnits from "./support/service-control-bridge-units.json" with { type: "json" };
import { syntheticYear, type YearUnit } from "./support/service-control-year.js";

type Unit = YearUnit & { readonly change: CheckedChange };

/** Every decision of one admission over `units`, in order, and its document at the end. */
function decide(
  units: readonly Unit[],
  options: ServiceControlOptions,
  mode: ConstructorParameters<typeof ServiceControlAdmission>[1],
) {
  const admission = new ServiceControlAdmission(options, mode);
  const latest = new Map<string, number>();
  const decisions = units.map(({ change, ...writer }) => {
    // §14.1 before admission, as the replica does: a taken sequence is held.
    if (change.seq <= (latest.get(change.actor) ?? 0)) return { held: true };
    try {
      checkServiceControlUnit(change, writer, options);
      const cls = admission.accept(change, writer);
      latest.set(change.actor, change.seq);
      return cls;
    } catch (e) {
      return { refused: `${(e as Error).name}: ${(e as { diagnostic?: string }).diagnostic}` };
    }
  });
  const doc = admission.document;
  return { decisions, heads: A.getHeads(doc).sort(), state: A.toJS(doc), judged: admission.judged };
}

/** A random order in which every change comes after its dependencies. */
function causalOrder(units: readonly Unit[], seed: number): Unit[] {
  let s = seed;
  const rnd = () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
  const left = [...units];
  const done = new Set<string>();
  const out: Unit[] = [];
  while (left.length > 0) {
    // Any ready change: one writer's changes arrive late, or early.
    const ready = left.flatMap((u, i) => (u.change.deps.every((d) => done.has(d)) ? [i] : []));
    const i = ready[Math.floor(rnd() * ready.length)] as number;
    const [u] = left.splice(i, 1) as [Unit];
    done.add(u.change.hash);
    out.push(u);
  }
  return out;
}

/** Changes judged at a fork point (a window of 256) and on the engine for want of a window (2). */
const paths = { forked: 0, engine: 0 };

function expectEquivalent(units: readonly Unit[], options: ServiceControlOptions) {
  const full = decide(units, options, { incremental: false });
  expect(full.judged.shadow).toBe(0);
  for (const window of [256, 2]) {
    const incremental = decide(units, options, { window });
    expect(incremental.decisions).toEqual(full.decisions);
    expect(incremental.heads).toEqual(full.heads);
    expect(incremental.state).toEqual(full.state);
    expect(incremental.judged.shadow).toBeGreaterThan(units.length * 0.9);
    if (window === 256) paths.forked += incremental.judged.forked;
    else paths.engine += incremental.judged.engine;
  }
  return full.decisions;
}

const withChanges = (units: readonly YearUnit[]): Unit[] =>
  units.map((u) => ({ ...u, change: checkChange(u.bytes) }));

describe("incremental admission of C decides as the engine path", () => {
  for (const seed of [1, 2, 3])
    it(`a synthetic fortnight with refused changes, written and causal orders (seed ${seed})`, () => {
      const year = syntheticYear({ days: 14, seed, refusals: true });
      const units = withChanges(year.units);
      const refusedAt = (decisions: readonly unknown[], order: readonly Unit[]) =>
        new Set(order.filter((_, i) => typeof decisions[i] === "object").map((u) => u.change.hash));
      const written = expectEquivalent(units, year.options);
      expect(year.strays.size).toBeGreaterThan(0);
      expect(refusedAt(written, units)).toEqual(year.strays);
      for (const order of [causalOrder(units, seed), causalOrder(units, seed + 100)]) {
        const decisions = expectEquivalent(order, year.options);
        expect(refusedAt(decisions, order)).toEqual(year.strays);
      }
    }, 300_000);

  it("the recorded units of the bridge's synthetic year, written and causal orders", () => {
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
    const units = withChanges(
      fixture.units.map((u) => ({
        signer: principalId(fromHex(u.signer)),
        actorSeq: u.seq,
        signerClass: u.cls,
        bytes: fromBase64url(u.bytes),
      })),
    );
    expectEquivalent(units, options);
    expectEquivalent(causalOrder(units, 5), options);
  }, 120_000);

  it("judged concurrent changes on the shadow and fell back to the engine beyond the window", () => {
    expect(paths.forked).toBeGreaterThan(20);
    expect(paths.engine).toBeGreaterThan(0);
  });

  it("the replica admits a synthetic history whole, as one batch and unit by unit", () => {
    const year = syntheticYear({ days: 3, seed: 9 });
    const whole = ServiceControlReplica.fromChanges(year.units, year.options);
    expect(whole.result.refused).toEqual([]);
    const one = ServiceControlReplica.empty(year.options);
    for (const u of year.units) expect(one.receiveChanges([u]).refused).toEqual([]);
    expect(one.heads()).toEqual(whole.replica.heads());
    expect(one.validate()).toEqual(whole.replica.validate());
  }, 120_000);
});

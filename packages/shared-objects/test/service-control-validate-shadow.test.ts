// A§3.5 (E-030j): ServiceControlReplica.validate() of the current state reads the shadow model, so
// a write or a receive validates what it changed instead of the whole document. It gives what §5
// gives on the engine's document (validate at explicit heads, which reads the engine) after every
// unit of bridge-style histories with refused and concurrent changes, received in the order written
// and in causal orders, and after the writes of a writer; and its cost does not grow with the
// history.

import { describe, expect, it } from "vitest";
import { checkChange } from "../src/admission/framing.js";
import { ServiceControlReplica } from "../src/service-control/index.js";
import { syntheticYear, type YearUnit } from "./support/service-control-year.js";

/** A random order in which every unit comes after the changes it depends on. */
function causalOrder(units: readonly YearUnit[], seed: number): YearUnit[] {
  let s = seed;
  const rnd = () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
  const left = units.map((u) => ({ u, deps: checkChange(u.bytes).deps }));
  const done = new Set<string>();
  const out: YearUnit[] = [];
  while (left.length > 0) {
    const ready = left.flatMap((x, i) => (x.deps.every((d) => done.has(d)) ? [i] : []));
    // A refused change's dependants never become ready: deliver what is left in order.
    const i = ready.length === 0 ? 0 : (ready[Math.floor(rnd() * ready.length)] as number);
    const [x] = left.splice(i, 1) as [{ u: YearUnit; deps: readonly string[] }];
    done.add(checkChange(x.u.bytes).hash);
    out.push(x.u);
  }
  return out;
}

function expectSameAsEngine(replica: ServiceControlReplica): void {
  expect(replica.validate()).toEqual(replica.validate(replica.heads()));
}

describe("validate() of C on the shadow model gives what the engine's document gives", () => {
  for (const seed of [1, 2])
    it(`after every unit of a synthetic fortnight with refusals, written and causal order (seed ${seed})`, () => {
      const year = syntheticYear({ days: 14, seed, refusals: true });
      for (const order of [year.units, causalOrder(year.units, seed)]) {
        const replica = ServiceControlReplica.empty(year.options);
        let refused = 0;
        for (const [i, u] of order.entries()) {
          refused += replica.receiveChanges([u]).refused.length;
          // Every unit early on, then every 7th (the engine's reads are the slow side).
          if (i < 200 || i % 7 === 0) expectSameAsEngine(replica);
        }
        expectSameAsEngine(replica);
        expect(refused).toBeGreaterThan(0);
      }
    }, 300_000);

  it("on a replica loaded from a Snapshot, then after each of its writes", () => {
    const year = syntheticYear({ days: 7, seed: 3 });
    const { replica: whole } = ServiceControlReplica.fromChanges(year.units, year.options);
    const replica = ServiceControlReplica.fromSnapshot(whole.snapshot(), year.options, year.units);
    expectSameAsEngine(replica);
    const bridge = year.units.at(-1) as YearUnit;
    const writer = { signer: bridge.signer, actorSeq: 2, signerClass: bridge.signerClass };
    const state = replica.validate();
    const binding = Object.keys(state.bindings)[0] as string;
    for (let n = 0; n < 40; n++) {
      replica.write(writer, [
        {
          intent: "status.put",
          fields: { heartbeatAt: `2026-03-01T00:${String(n).padStart(2, "0")}:00Z` },
        },
      ]);
      if (n % 3 === 0)
        replica.write(writer, [
          { intent: "binding.put", binding, fields: { pending: { toApple: n, toLfcp: 0 } } },
        ]);
      expectSameAsEngine(replica);
    }
  }, 120_000);

  it("costs the same at the end of a long history as at its start, and less than the engine", () => {
    // On the engine, every read walks the history of its key (one more operation per
    // heartbeat); on the shadow, readings of unchanged objects are reused.
    const year = syntheticYear({ days: 60, seed: 5 });
    const replica = ServiceControlReplica.empty(year.options);
    const cost = (from: number, to: number) => {
      replica.receiveChanges(year.units.slice(0, from));
      let shadow = 0;
      for (const u of year.units.slice(from, to)) {
        replica.receiveChanges([u]);
        const t = performance.now();
        replica.validate();
        shadow += performance.now() - t;
      }
      return shadow / (to - from);
    };
    const early = cost(200, 600);
    const n = year.units.length;
    const late = cost(n - 400, n);
    const t = performance.now();
    for (let i = 0; i < 20; i++) replica.validate(replica.heads());
    const engine = (performance.now() - t) / 20;
    expect(late).toBeLessThan(early * 3 + 0.2);
    expect(late * 4).toBeLessThan(engine);
  }, 300_000);
});

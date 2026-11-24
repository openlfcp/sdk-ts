// A§3.5 (E-030): the service writes heartbeat only with a change or every 30 min, and the status
// and each binding at most once a minute, the transitions inside that minute merged.

import { describe, expect, it } from "vitest";
import { checkChange } from "../src/admission/framing.js";
import {
  HEARTBEAT_INTERVAL_MS,
  ServiceControlReplica,
  ServiceControlStatusSchedule,
  TRANSITION_INTERVAL_MS,
} from "../src/service-control/index.js";
import { syntheticYear } from "./support/service-control-year.js";

const T0 = Date.parse("2026-01-05T00:00:00Z");
const MIN = 60_000;
const iso = (t: number) => new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");

/** Runs the schedule minute by minute, writing a unit whenever one is due. */
function run(s: ServiceControlStatusSchedule, minutes: number, at = T0) {
  const units: { at: number; intents: ReturnType<ServiceControlStatusSchedule["take"]> }[] = [];
  for (let t = at; t < at + minutes * MIN; t += 1000)
    if (s.due(t)) units.push({ at: t, intents: s.take(t) });
  return units;
}

describe("A§3.5 heartbeat", () => {
  it("is written every 30 min when nothing changes, and not more often", () => {
    const s = new ServiceControlStatusSchedule(T0);
    expect(s.due(T0 + HEARTBEAT_INTERVAL_MS - 1)).toBe(false);
    const units = run(s, 24 * 60, T0 + 1000);
    expect(units).toHaveLength(48);
    for (const [n, u] of units.entries()) {
      expect(u.at).toBe(T0 + (n + 1) * HEARTBEAT_INTERVAL_MS);
      expect(u.intents).toEqual([{ intent: "status.put", fields: { heartbeatAt: iso(u.at) } }]);
    }
  });

  it("rides a change, which restarts its 30 min", () => {
    const s = new ServiceControlStatusSchedule(T0);
    s.binding("b1", { refused: 1 });
    expect(s.take(T0 + 10 * MIN)).toEqual([
      { intent: "status.put", fields: { heartbeatAt: iso(T0 + 10 * MIN) } },
      { intent: "binding.put", binding: "b1", fields: { refused: 1 } },
    ]);
    expect(s.nextAt()).toBe(T0 + 40 * MIN);
  });

  it("a deferred field never makes a unit before the heartbeat, then rides it", () => {
    const s = new ServiceControlStatusSchedule(T0);
    s.binding("b1", { lastCompleteCheckAt: iso(T0 + MIN) }, { defer: true });
    s.binding("b1", { lastCompleteCheckAt: iso(T0 + 7 * MIN) }, { defer: true });
    expect(s.nextAt()).toBe(T0 + HEARTBEAT_INTERVAL_MS);
    const [unit, ...rest] = run(s, 60, T0 + 1000);
    expect(unit?.intents).toEqual([
      { intent: "status.put", fields: { heartbeatAt: iso(T0 + HEARTBEAT_INTERVAL_MS) } },
      { intent: "binding.put", binding: "b1", fields: { lastCompleteCheckAt: iso(T0 + 7 * MIN) } },
    ]);
    expect(rest.map((u) => u.at)).toEqual([T0 + 2 * HEARTBEAT_INTERVAL_MS]);
  });
});

describe("A§3.5 transitions", () => {
  it("are written at once, at most once a minute per binding, merged inside the minute", () => {
    const s = new ServiceControlStatusSchedule(T0);
    s.binding("b1", { state: "on", pending: { toApple: 3, toLfcp: 0 } });
    expect(s.due(T0)).toBe(true);
    expect(s.take(T0)).toHaveLength(2);
    // Three transitions of b1 within its minute: held, then one write of the last values.
    s.binding("b1", { pending: { toApple: 2, toLfcp: 0 } });
    s.binding("b1", { pending: { toApple: 0, toLfcp: 0 }, unconfirmed: 1 });
    s.binding("b1", { lastCompleteCheckAt: iso(T0 + 30_000) }, { defer: true });
    expect(s.due(T0 + TRANSITION_INTERVAL_MS - 1)).toBe(false);
    expect(s.nextAt()).toBe(T0 + TRANSITION_INTERVAL_MS);
    expect(s.take(T0 + TRANSITION_INTERVAL_MS)).toEqual([
      { intent: "status.put", fields: { heartbeatAt: iso(T0 + TRANSITION_INTERVAL_MS) } },
      {
        intent: "binding.put",
        binding: "b1",
        fields: {
          pending: { toApple: 0, toLfcp: 0 },
          unconfirmed: 1,
          lastCompleteCheckAt: iso(T0 + 30_000),
        },
      },
    ]);
  });

  it("of one binding do not hold back another's, nor the status", () => {
    const s = new ServiceControlStatusSchedule(T0);
    s.binding("b1", { refused: 1 });
    s.take(T0);
    s.binding("b1", { refused: 2 });
    s.binding("b2", { refused: 5 });
    s.status({ state: "paused", since: iso(T0 + 1000) });
    expect(s.due(T0 + 1000)).toBe(true);
    expect(s.take(T0 + 1000)).toEqual([
      {
        intent: "status.put",
        fields: { state: "paused", since: iso(T0 + 1000), heartbeatAt: iso(T0 + 1000) },
      },
      { intent: "binding.put", binding: "b2", fields: { refused: 5 } },
    ]);
    // b1 and the status each wait for their own minute.
    s.status({ state: "running", since: iso(T0 + 2000) });
    const units = run(s, 2, T0 + 2000);
    const b1 = T0 + TRANSITION_INTERVAL_MS;
    const status = T0 + 1000 + TRANSITION_INTERVAL_MS;
    expect(units).toEqual([
      {
        at: b1,
        intents: [
          { intent: "status.put", fields: { heartbeatAt: iso(b1) } },
          { intent: "binding.put", binding: "b1", fields: { refused: 2 } },
        ],
      },
      {
        at: status,
        intents: [
          {
            intent: "status.put",
            fields: { state: "running", since: iso(T0 + 2000), heartbeatAt: iso(status) },
          },
        ],
      },
    ]);
  });

  it("at most one write a minute per binding under a burst, the last values kept", () => {
    const s = new ServiceControlStatusSchedule(T0);
    const writes: number[] = [];
    let last: unknown;
    for (let t = T0; t < T0 + 10 * MIN; t += 5000) {
      s.binding("b1", { pending: { toApple: (t - T0) / 5000, toLfcp: 0 } });
      if (!s.due(t)) continue;
      const unit = s.take(t);
      writes.push(t);
      last = unit.find((i) => i.intent === "binding.put");
    }
    for (let i = 1; i < writes.length; i++)
      expect((writes[i] as number) - (writes[i - 1] as number)).toBeGreaterThanOrEqual(
        TRANSITION_INTERVAL_MS,
      );
    expect(writes).toHaveLength(10);
    expect(last).toEqual({
      intent: "binding.put",
      binding: "b1",
      fields: { pending: { toApple: 108, toLfcp: 0 } },
    });
  });
});

describe("A§3.5 the write-frequency reduction keeps C's dedup evidence", () => {
  it("every answer stays in the history after cleanup, from a daily Snapshot and its tail too", () => {
    const year = syntheticYear({ days: 14 });
    const { replica, result } = ServiceControlReplica.fromChanges(year.units, year.options);
    expect(result.refused).toEqual([]);
    // The root's units after initialize and the approval are its answers (A§3.4 step 4 dedups on them).
    const answers = year.units.filter((u) => u.signerClass === "root").slice(2);
    expect(answers.length).toBeGreaterThan(10);
    // Cleaned up from the state readers see, never from the history.
    expect(Object.keys(replica.validate().answers).length).toBeLessThan(answers.length);
    for (const u of year.units) expect(replica.hasChange(checkChange(u.bytes).hash)).toBe(true);

    const at = year.snapshots.at(-2) as number;
    expect(year.snapshots).toHaveLength(14);
    const prefix = year.units.slice(0, at);
    const snapshot = ServiceControlReplica.fromChanges(prefix, year.options).replica.snapshot();
    const cold = ServiceControlReplica.fromSnapshot(snapshot, year.options, prefix);
    expect(cold.receiveChanges(year.units.slice(at)).refused).toEqual([]);
    expect(cold.heads()).toEqual(replica.heads());
    for (const u of answers) expect(cold.hasChange(checkChange(u.bytes).hash)).toBe(true);
  }, 60_000);
});

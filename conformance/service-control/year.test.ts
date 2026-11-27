// A§3.5 (E-030): admission and cold connect of C on a bridge-style synthetic history, against the
// budget (admission ≤ 5 s, cold connect ≤ 10 s). Measured, not held: LFCP_SC_YEAR=14,365 runs
// those lengths in days and prints the figures (the bridge's nightly c-year job holds the whole
// client to the budget). Cold connect here is the SDK's part: the replica from the plugin's latest
// Snapshot (weekly) and the units it carries, the tail after it, then the reads a client makes of C (validate, creatorsOf, requestHistory), here and
// again in a process of its own for its peak RSS (budget ≤ 350 MiB, enforced; cold-client.mjs). The RSS budget is measured with a capped V8 heap
// (--max-old-space-size=200 --max-semi-space-size=4, V8_CAPS in cold-client.mjs); hosts are
// recommended to run their cold client with similar caps.

import { checkChange } from "@openlfcp/shared-objects/admission";
import {
  ServiceControlAdmission,
  ServiceControlReplica,
} from "@openlfcp/shared-objects/service-control";
import { describe, expect, it } from "vitest";
import { syntheticYear } from "../../packages/shared-objects/test/support/service-control-year.js";
import { measureColdClient } from "./cold-client.mjs";

const DAYS = (process.env.LFCP_SC_YEAR ?? "")
  .split(",")
  .filter((d) => d !== "")
  .map(Number);

const timed = <T>(f: () => T): [T, number] => {
  const t = performance.now();
  const r = f();
  return [r, Math.round(performance.now() - t)];
};

describe.skipIf(DAYS.length === 0)("A§3.5 admission and cold connect of C", () => {
  for (const days of DAYS)
    it(`${days} days of bridge-style history`, () => {
      const [year, generate] = timed(() => syntheticYear({ days, snapshotEveryDays: 7 }));
      const bytes = year.units.reduce((n, u) => n + u.bytes.length, 0);
      // The worst case: a client connecting just before the plugin's next Snapshot, the tail a
      // whole period (the last Snapshot is taken at the end of the history).
      const at = year.snapshots.at(-2) ?? year.units.length;
      const [prefix, tail] = [year.units.slice(0, at), year.units.slice(at)];
      const [admitted, before] = timed(() =>
        ServiceControlReplica.fromChanges(prefix, year.options),
      );
      expect(admitted.result.refused).toEqual([]);
      const replica = admitted.replica;
      const snapshot = replica.snapshot();
      const [rest, after] = timed(() => replica.receiveChanges(tail));
      expect(rest.refused).toEqual([]);
      const admission = before + after;
      const [, engine] =
        days <= 31
          ? timed(() => {
              const full = new ServiceControlAdmission(year.options, { incremental: false });
              // The engine path alone, as before E-030 (admission only, no sequence checks).
              for (const u of year.units) full.accept(checkChange(u.bytes), u);
            })
          : [undefined, Number.NaN];
      const [cold, fromSnapshot] = timed(() =>
        ServiceControlReplica.fromSnapshot(snapshot, year.options, prefix),
      );
      const [, tailMs] = timed(() => cold.receiveChanges(tail));
      const [state, validate] = timed(() => cold.validate());
      const [, creatorsOf] = timed(() => {
        cold.creatorsOf("bindings", Object.keys(state.bindings)[0] ?? "");
        cold.creatorsOf("approvals", Object.keys(state.approvals)[0] ?? "");
      });
      const [, requestHistory] = timed(() => cold.requestHistory());
      const figures = {
        days,
        units: year.units.length,
        historyMiB: +(bytes / 2 ** 20).toFixed(2),
        generateMs: generate,
        admissionMs: admission,
        engineAdmissionMs: engine,
        tailUnits: tail.length,
        coldConnectMs: fromSnapshot + tailMs + validate + creatorsOf + requestHistory,
        cold: { fromSnapshot, tail: tailMs, validate, creatorsOf, requestHistory },
        heapMiB: Math.round(process.memoryUsage().heapUsed / 2 ** 20),
        rssMiB: Math.round(process.memoryUsage().rss / 2 ** 20),
        coldClient: measureColdClient(snapshot, year.units, tail.length, year.options),
      };
      console.info(`E-030 C admission: ${JSON.stringify(figures)}`);
      // A§3.5: admission ≤ 5 s, cold connect ≤ 10 s (the cold client loads the Snapshot through
      // ServiceControlDataProfile.snapshotBinding().load, §2.5).
      expect(figures.admissionMs).toBeLessThanOrEqual(5_000);
      expect(figures.coldClient.coldConnectMs).toBeLessThanOrEqual(10_000);
      // Peak RSS ≤ 350 MiB is the third budget (ARCHITECTURE §3.5, owner decision: the JS client's
      // cold-connect peak at 365 days of C; 200 MiB is not required). Always enforced.
      expect(figures.coldClient.peakRssMiB).toBeLessThanOrEqual(350);
    }, 3_600_000);
});

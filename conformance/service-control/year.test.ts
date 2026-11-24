// A§3.5 (E-030): admission and cold connect of C on a bridge-style synthetic history, against the
// budget (admission ≤ 5 s, cold connect ≤ 10 s). Measured, not held: LFCP_SC_YEAR=14,365 runs
// those lengths in days and prints the figures (the bridge's nightly c-year job holds the whole
// client to the budget). Cold connect here is the SDK's part: the replica from a Snapshot and
// every unit, then the reads a client makes of C (validate, creatorsOf, requestHistory).

import { checkChange } from "@openlfcp/shared-objects/admission";
import {
  ServiceControlAdmission,
  ServiceControlReplica,
} from "@openlfcp/shared-objects/service-control";
import { describe, expect, it } from "vitest";
import { syntheticYear } from "../../packages/shared-objects/test/support/service-control-year.js";

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
      const [year, generate] = timed(() => syntheticYear({ days }));
      const bytes = year.units.reduce((n, u) => n + u.bytes.length, 0);
      const [admitted, admission] = timed(() =>
        ServiceControlReplica.fromChanges(year.units, year.options),
      );
      expect(admitted.result.refused).toEqual([]);
      const replica = admitted.replica;
      const snapshot = replica.snapshot();
      const [, engine] =
        days <= 31
          ? timed(() => {
              const full = new ServiceControlAdmission(year.options, { incremental: false });
              // The engine path alone, as before E-030 (admission only, no sequence checks).
              for (const u of year.units) full.accept(checkChange(u.bytes), u);
            })
          : [undefined, Number.NaN];
      const [cold, fromSnapshot] = timed(() =>
        ServiceControlReplica.fromSnapshot(snapshot, year.options, year.units),
      );
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
        coldConnectMs: fromSnapshot + validate + creatorsOf + requestHistory,
        cold: { fromSnapshot, validate, creatorsOf, requestHistory },
        heapMiB: Math.round(process.memoryUsage().heapUsed / 2 ** 20),
        rssMiB: Math.round(process.memoryUsage().rss / 2 ** 20),
      };
      console.info(`E-030 C admission: ${JSON.stringify(figures)}`);
    }, 3_600_000);
});

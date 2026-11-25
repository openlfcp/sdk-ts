// A§3.5 (E-030): a cold client of C decodes each change once. Building the replica from a
// Snapshot and the units that carry its changes, admitting the tail and making a client's reads
// walk each change's bytes once (the canonical walk of §11.3); admission reads the operations
// from that walk, in the form the engine's decode gives them, without decoding the bytes again.

import * as A from "@automerge/automerge";
import { describe, expect, it } from "vitest";
import { changeDecodeCount, checkChange, decodedView } from "../src/admission/framing.js";
import { ServiceControlReplica } from "../src/service-control/index.js";
import { syntheticYear } from "./support/service-control-year.js";

describe("A§3.5 decode once on a cold client of C", () => {
  const year = syntheticYear({ days: 4 });
  const at = year.snapshots.at(-2) ?? year.units.length;
  const [prefix, tail] = [year.units.slice(0, at), year.units.slice(at)];

  it("decodes each change of the Snapshot and the tail exactly once", () => {
    const snapshot = ServiceControlReplica.fromChanges(prefix, year.options).replica.snapshot();
    expect(tail.length).toBeGreaterThan(0);
    const before = changeDecodeCount();
    const cold = ServiceControlReplica.fromSnapshot(snapshot, year.options, prefix);
    expect(cold.receiveChanges(tail).refused).toEqual([]);
    const state = cold.validate();
    cold.creatorsOf("bindings", Object.keys(state.bindings)[0] ?? "");
    cold.requestHistory();
    expect(changeDecodeCount() - before).toBe(year.units.length);
  });

  it("reads each change as the engine's decode gives it", () => {
    for (const { bytes } of year.units) {
      const view = decodedView(checkChange(bytes));
      const engine = A.decodeChange(bytes);
      for (const field of ["hash", "actor", "seq", "startOp", "time", "deps", "ops"] as const)
        expect(view[field]).toEqual(engine[field]);
    }
  });
});

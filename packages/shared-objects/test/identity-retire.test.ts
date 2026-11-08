import * as A from "@automerge/automerge";
import { describe, expect, test } from "vitest";
import { IdentityReplica } from "../src/identity/index.js";
import {
  device,
  edit,
  filled,
  options,
  personalWriter,
  rootWriter,
  S,
  unit,
} from "./support/identity.js";

// IdentityReplica's field-level access to a retired entry's flag
// (IDENTITY-PROFILE-01 §7.1 step 4, §8.2; review LFCP-04-415f finding 3):
// every concurrent value of `revoked`, and a change that sets it and writes
// no other field of the entry. The planner side is
// conformance/identity/replica-retire.test.ts.

const keysOf = (bytes: Uint8Array) => A.decodeChange(bytes).ops.map((o) => o.key);

const conflicted = (field: "label" | "revoked", values: readonly [unknown, unknown]) => {
  const f = filled();
  const a = edit(
    f.doc,
    (d) => {
      d.devices[device.key][field] = typeof values[0] === "string" ? S(values[0]) : values[0];
    },
    { ...rootWriter, actorSeq: 3 },
  );
  const b = edit(
    f.doc,
    (d) => {
      d.devices[device.key][field] = typeof values[1] === "string" ? S(values[1]) : values[1];
    },
    personalWriter,
  );
  const r = IdentityReplica.fromChanges(
    [...f.units, unit(a, { ...rootWriter, actorSeq: 3 }), unit(b, personalWriter)],
    options,
  ).replica;
  expect(r.validate().problems).toEqual([]);
  return r;
};

describe("IdentityReplica: a retired entry's flag field by field", () => {
  test("retire writes `revoked` alone", () => {
    const r = IdentityReplica.fromChanges(filled().units, options).replica;
    expect(r.fieldValues("devices", device.key, "revoked")).toEqual([]);
    const change = r.write({ ...rootWriter, actorSeq: 3 }, [], { retire: [device.key] });
    expect(keysOf(change.bytes)).toEqual(["revoked"]);
    expect(r.fieldValues("devices", device.key, "revoked")).toEqual([true]);
  });

  test("retire leaves a label conflict as it is; a whole-entry put would resolve it", () => {
    const r = conflicted("label", ["alpha", "beta"]);
    expect([...r.fieldValues("devices", device.key, "label")].sort()).toEqual(["alpha", "beta"]);
    const change = r.write({ ...rootWriter, actorSeq: 4 }, [], { retire: [device.key] });
    expect(keysOf(change.bytes)).toEqual(["revoked"]);
    expect([...r.fieldValues("devices", device.key, "label")].sort()).toEqual(["alpha", "beta"]);
    // 0.4's flag write, the display fields put again, resolves the conflict.
    const shown = r.devices()[device.key];
    const put = conflicted("label", ["alpha", "beta"]).write(
      { ...rootWriter, actorSeq: 4 },
      {
        intent: "device.put",
        key: device.key,
        entry: { ...(shown as NonNullable<typeof shown>), revoked: true },
      },
    );
    expect(keysOf(put.bytes)).toContain("label");
  });

  test("every value of a true/false conflict is seen, and retire leaves true alone", () => {
    const r = conflicted("revoked", [false, true]);
    expect([...r.fieldValues("devices", device.key, "revoked")].sort()).toEqual([false, true]);
    const change = r.write({ ...rootWriter, actorSeq: 4 }, [], { retire: [device.key] });
    expect(keysOf(change.bytes)).toEqual(["revoked"]);
    expect(r.fieldValues("devices", device.key, "revoked")).toEqual([true]);
  });

  test("retire refuses an entry that does not exist, and an empty write", () => {
    const r = IdentityReplica.fromChanges(filled().units, options).replica;
    expect(r.fieldValues("devices", "p:nobody", "revoked")).toEqual([]);
    expect(() => r.write({ ...rootWriter, actorSeq: 3 }, [], { retire: ["p:nobody"] })).toThrow();
    expect(() => r.write({ ...rootWriter, actorSeq: 3 }, [])).toThrow();
  });
});

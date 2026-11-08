// IDENTITY-PROFILE-01 §7.1 step 4 on a retired entry, through the real
// IdentityReplica and its IdentityDocumentPort (review LFCP-04-415f finding
// 3): reconciliation writes `revoked = true` when some value of the flag is
// not true, and writes nothing else into the entry, so it never resolves a
// conflict on its display fields.

import { type DeviceEntryValue, planDisplayData } from "@openlfcp/client";
import { fromBase64url, principalId, toHex } from "@openlfcp/core";
import { IdentityReplica } from "@openlfcp/shared-objects/identity";
import type { ControlState } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import {
  device,
  edit,
  filled,
  options,
  personalWriter,
  root,
  rootWriter,
  S,
  unit,
} from "../../packages/shared-objects/test/support/identity.js";

const D = principalId(fromBase64url(device.key.slice(2)));
// I's Control state as step 4 reads it: D is a personal device of the root, bound as a
// leaf, and revoked; its entry is a retired entry.
const state = {
  devices: new Map([[toHex(D), { root, kind: 0, chain: {} }]]),
  revoked: new Map([[`${toHex(root)}:${toHex(D)}`, { root, device: D }]]),
} as unknown as ControlState;

/** IdentityDocumentPort.retirement.revokedValues over a replica (replicaPort, storage-node). */
const revokedValues = (r: IdentityReplica) => (key: string) =>
  r.fieldValues("devices", key, "revoked");
const plan = (r: IdentityReplica) =>
  planDisplayData(
    state,
    new Map(Object.entries(r.devices())) as Map<string, DeviceEntryValue>,
    root,
    revokedValues(r),
  );

describe("a retired entry's flag (IDENTITY-PROFILE-01 §7.1 step 4)", () => {
  test("only `revoked` is written into a retired entry", () => {
    const r = IdentityReplica.fromChanges(filled().units, options).replica;
    const p = plan(r);
    expect(p).toEqual({ intents: [], retire: [device.key] });
    r.write({ ...rootWriter, actorSeq: 3 }, p.intents, { retire: p.retire });
    expect(r.devices()[device.key]).toEqual({ label: "phone", kind: 0, revoked: true });
    // A second run plans nothing.
    expect(plan(r)).toEqual({ intents: [], retire: [] });
  });

  test("an existing label conflict is not resolved by retiring the entry", () => {
    const f = filled();
    const a = edit(
      f.doc,
      (d) => {
        d.devices[device.key].label = S("alpha");
      },
      { ...rootWriter, actorSeq: 3 },
    );
    const b = edit(
      f.doc,
      (d) => {
        d.devices[device.key].label = S("beta");
      },
      personalWriter,
    );
    const r = IdentityReplica.fromChanges(
      [...f.units, unit(a, { ...rootWriter, actorSeq: 3 }), unit(b, personalWriter)],
      options,
    ).replica;
    expect(r.validate().problems).toEqual([]);
    expect([...r.fieldValues("devices", device.key, "label")].sort()).toEqual(["alpha", "beta"]);
    const p = plan(r);
    expect(p).toEqual({ intents: [], retire: [device.key] });
    r.write({ ...rootWriter, actorSeq: 4 }, p.intents, { retire: p.retire });
    // The conflict on the label is still there (the change's ops: packages/shared-objects/test/identity-retire.test.ts).
    expect([...r.fieldValues("devices", device.key, "label")].sort()).toEqual(["alpha", "beta"]);
  });

  test("a true/false conflict is reconciled even when the value shown is true", () => {
    const f = filled();
    let checked = false;
    // The same actors with the values swapped: one variant necessarily shows true.
    for (const rootValue of [false, true]) {
      const a = edit(
        f.doc,
        (d) => {
          d.devices[device.key].revoked = rootValue;
        },
        { ...rootWriter, actorSeq: 3 },
      );
      const b = edit(
        f.doc,
        (d) => {
          d.devices[device.key].revoked = !rootValue;
        },
        personalWriter,
      );
      const r = IdentityReplica.fromChanges(
        [...f.units, unit(a, { ...rootWriter, actorSeq: 3 }), unit(b, personalWriter)],
        options,
      ).replica;
      expect(r.validate().problems).toEqual([]);
      expect([...r.fieldValues("devices", device.key, "revoked")].sort()).toEqual([false, true]);
      if (r.devices()[device.key]?.revoked !== true) continue;
      checked = true;
      // Without the port's values the one shown value hides the conflict.
      expect(
        planDisplayData(
          state,
          new Map(Object.entries(r.devices())) as Map<string, DeviceEntryValue>,
          root,
        ).retire,
      ).toEqual([]);
      const p = plan(r);
      expect(p.retire).toEqual([device.key]);
      r.write({ ...rootWriter, actorSeq: 4 }, p.intents, { retire: p.retire });
      expect(r.fieldValues("devices", device.key, "revoked")).toEqual([true]);
      expect(plan(r).retire).toEqual([]);
    }
    expect(checked).toBe(true);
  });

  test("a retired entry without the field gets it; a valid entry is never created for a revoked device", () => {
    const f = filled();
    const r = IdentityReplica.fromChanges(f.units, options).replica;
    expect(r.fieldValues("devices", device.key, "revoked")).toEqual([]);
    expect(r.fieldValues("devices", "p:nobody", "revoked")).toEqual([]);
    expect(() => r.write({ ...rootWriter, actorSeq: 3 }, [], { retire: ["p:nobody"] })).toThrow();
  });
});

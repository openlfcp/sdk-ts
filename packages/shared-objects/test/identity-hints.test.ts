import * as A from "@automerge/automerge";
import { describe, expect, test } from "vitest";
import { IdentityReplica } from "../src/identity/index.js";
import { principalRef } from "../src/values.js";
import {
  edit,
  filled,
  options,
  personalWriter,
  resourceRef,
  root,
  rootWriter,
  S,
  unit,
} from "./support/identity.js";

// IdentityReplica's field-level write of a device's own `missing_keys` hint
// (IDENTITY-PROFILE-01 §7.1 step 3, §3 AI5; design 419 (a)): only
// `devices[<writer>].missing_keys` is written, never the label or another
// field, so a concurrent rename stays a conflict; an empty hint removes the
// field. The root counts as the device of its own entry (AI5).

const me = principalRef(root);
const other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const opsOf = (bytes: Uint8Array) =>
  A.decodeChange(bytes).ops.map((o) => `${o.action}:${String(o.key)}`);

/** `filled()` plus the root's own entry, and optionally a concurrent rename of it by another writer. */
function withOwnEntry(conflict = false) {
  const f = filled();
  const own = edit(
    f.doc,
    (d) => {
      d.devices[me] = { label: S("laptop") };
    },
    { ...rootWriter, actorSeq: 3 },
  );
  const units = [...f.units, unit(own, { ...rootWriter, actorSeq: 3 })];
  if (conflict) {
    const a = edit(
      own,
      (d) => {
        d.devices[me].label = S("desk");
      },
      { ...rootWriter, actorSeq: 4 },
    );
    const b = edit(
      own,
      (d) => {
        d.devices[me].label = S("work");
      },
      personalWriter,
    );
    units.push(unit(a, { ...rootWriter, actorSeq: 4 }), unit(b, personalWriter));
  }
  const r = IdentityReplica.fromChanges(units, options).replica;
  expect(r.validate().problems).toEqual([]);
  return { r, units, next: conflict ? 5 : 4 };
}

describe("IdentityReplica: a device's own missing_keys hint, field by field", () => {
  test("a hint writes missing_keys alone, and a receiver admits it", () => {
    const { r, units, next } = withOwnEntry();
    const writer = { ...rootWriter, actorSeq: next };
    const change = r.write(writer, [], { hints: new Map([[resourceRef, [1n, 2n]]]) });
    expect(opsOf(change.bytes).some((o) => o.endsWith(":label") || o.endsWith(":kind"))).toBe(
      false,
    );
    expect(r.devices()[me]?.missing_keys).toEqual({ [resourceRef]: [1, 2] });
    const received = IdentityReplica.fromChanges(
      [...units, { ...writer, bytes: change.bytes }],
      options,
    );
    expect(received.result.refused).toEqual([]);
    expect(received.replica.devices()[me]?.missing_keys).toEqual({ [resourceRef]: [1, 2] });
  });

  test("a rename conflict stays a conflict; a whole-entry put would resolve it", () => {
    const { r, next } = withOwnEntry(true);
    expect([...r.fieldValues("devices", me, "label")].sort()).toEqual(["desk", "work"]);
    r.write({ ...rootWriter, actorSeq: next }, [], { hints: new Map([[resourceRef, [3n]]]) });
    expect([...r.fieldValues("devices", me, "label")].sort()).toEqual(["desk", "work"]);
    expect(r.devices()[me]?.missing_keys).toEqual({ [resourceRef]: [3] });
  });

  test("updating one Resource keeps the others; removing the last removes the field", () => {
    const { r, next } = withOwnEntry();
    r.write({ ...rootWriter, actorSeq: next }, [], {
      hints: new Map([
        [resourceRef, [1n]],
        [other, [4n]],
      ]),
    });
    r.write({ ...rootWriter, actorSeq: next + 1 }, [], { hints: new Map([[resourceRef, null]]) });
    expect(r.devices()[me]?.missing_keys).toEqual({ [other]: [4] });
    r.write({ ...rootWriter, actorSeq: next + 2 }, [], { hints: new Map([[other, []]]) });
    expect(r.devices()[me]?.missing_keys).toBeUndefined();
    expect(r.fieldValues("devices", me, "missing_keys")).toEqual([]);
  });

  test("a hint needs the writer's own entry; an empty write is refused", () => {
    const r = IdentityReplica.fromChanges(filled().units, options).replica;
    expect(() =>
      r.write({ ...rootWriter, actorSeq: 3 }, [], { hints: new Map([[resourceRef, [1n]]]) }),
    ).toThrow(/no device entry/);
    expect(() => r.write({ ...rootWriter, actorSeq: 3 }, [], { hints: new Map() })).toThrow();
  });
});

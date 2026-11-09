// AI3 positions beyond the corpus (decisions I27, I32): the nine cases sdk-rs
// 417-ai3-links pins in ai3_checks_only_the_positions_the_profile_defines, with
// the same verdicts (review 419 round 2: the reviewer's differential probe).
import * as A from "@automerge/automerge";
import { expect, test } from "vitest";
import { IdentityReplica } from "../src/identity/index.js";
import { principalRef } from "../src/values.js";
import {
  actor,
  type Doc,
  filled,
  options,
  resourceRef,
  rootWriter,
  S,
  U,
  unit,
} from "./support/identity.js";

const me = principalRef(options.root);
const Y = "Y".repeat(43);
const change = (doc: A.Doc<Doc>, fn: (d: Doc) => void) =>
  A.change(A.clone(doc, { actor: actor(rootWriter) }), { time: 0 }, fn);

test("AI3 decides by position as sdk-rs does, beyond the corpus", () => {
  const f = filled();
  const own = change(f.doc, (d) => {
    d.devices[me] = { label: S("laptop"), kind: U(0) };
    d.devices[me].missing_keys = {};
    d.devices[me].missing_keys[resourceRef] = [];
    d.devices[me].missing_keys[resourceRef][0] = U(1);
  });
  const base = [...f.units, unit(own, { ...rootWriter, actorSeq: 3 })];
  const r0 = IdentityReplica.fromChanges(base, options);
  expect(r0.result.refused).toEqual([]);
  const cases: [string, (d: Doc) => void, string][] = [
    [
      "list as an element of endpoints",
      (d) => d.roster[resourceRef].endpoints.insertAt(0, []),
      "INVALID_FIELD_TYPE",
    ],
    [
      "signed int as an element of endpoints",
      (d) => d.roster[resourceRef].endpoints.insertAt(0, 1),
      "INVALID_FIELD_TYPE",
    ],
    [
      "counter in extensions[ns]",
      (d) => {
        d.extensions["com.example.c"] = new A.Counter(1);
      },
      "admitted",
    ],
    [
      "signed int in a list below name",
      (d) => {
        d.roster[resourceRef].name = [];
        d.roster[resourceRef].name.insertAt(0, -1);
      },
      "admitted",
    ],
    [
      "f64 under key [] of an unknown field",
      (d) => {
        d.roster[resourceRef].ext = {};
        d.roster[resourceRef].ext["[]"] = new A.Float64(1.5);
      },
      "admitted",
    ],
    // `scope` is no roster field (only requests[k] and devices[k] define it): not checked
    // (review 417-418, sdk-rs pins the same).
    [
      "signed int -1 in a list at roster[X].scope",
      (d) => {
        d.roster[resourceRef].scope = [];
        // A signed int (datatype int) -1, as the backend writes it: Automerge's JS proxy
        // would write -1 as an f64 and a wrapped Int as a map.
        const list = A.getObjectId(d.roster[resourceRef].scope) as string;
        A.getBackend(d as never).insert(list, 0, -1, "int");
      },
      "admitted",
    ],
    [
      "signed int as an element of own missing_keys[X]",
      (d) => d.devices[me].missing_keys[resourceRef].insertAt(0, 3),
      "INVALID_FIELD_TYPE",
    ],
    [
      "signed int as own hint entry missing_keys[Y]",
      (d) => {
        d.devices[me].missing_keys[Y] = new A.Int(3);
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "map holding a signed int as own hint entry",
      (d) => {
        d.devices[me].missing_keys[Y] = {};
        d.devices[me].missing_keys[Y].a = new A.Int(-1);
      },
      "admitted",
    ],
    [
      "list replacing own missing_keys, holding a map",
      (d) => {
        d.devices[me].missing_keys = [];
        d.devices[me].missing_keys.insertAt(0, {});
      },
      "admitted",
    ],
  ];
  for (const [name, fn, want] of cases) {
    const next = change(own, fn);
    const ops = A.decodeChange(A.getLastLocalChange(next) as Uint8Array).ops.map(
      (o) => `${o.action}${o.datatype ? `/${o.datatype}` : ""}`,
    );
    const r = IdentityReplica.fromChanges(
      [...base, unit(next, { ...rootWriter, actorSeq: 4 })],
      options,
    );
    const got =
      r.result.refused.length === 0 && r.result.waiting.length === 0
        ? "admitted"
        : (r.result.refused[0]?.diagnostic ?? "waiting");
    expect(`${name}: ${got} (${ops.join(",")})`).toBe(`${name}: ${want} (${ops.join(",")})`);
  }
});

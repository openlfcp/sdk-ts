import * as A from "@automerge/automerge";
import { UINT64_MAX } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange, frameChange, MAX_DOCUMENT_DEPTH } from "../src/admission/index.js";
import { IdentityReplica, identityCodec, identitySnapshotCodec } from "../src/identity/index.js";
import { deriveActorId, parsePrincipalRef, principalRef } from "../src/values.js";
import {
  actor,
  type Doc,
  device,
  edit,
  filled,
  initial,
  last,
  options,
  pairingWriter,
  personalWriter,
  resource,
  resourceRef,
  root,
  rootWriter,
  S,
  unit,
} from "./support/identity.js";

describe("identity replica / ID-05", () => {
  it("identity_doc_initial_then_fill: both delivery orders and dependency buffering", () => {
    const { units } = filled();
    const normal = IdentityReplica.fromChanges(units, options);
    const reverse = IdentityReplica.fromChanges([...units].reverse(), options);
    expect(normal.result.refused).toEqual([]);
    expect(reverse.result.refused).toEqual([]);
    expect(reverse.replica.validate()).toEqual(normal.replica.validate());
    const r = IdentityReplica.empty(options);
    expect(r.receiveChanges([units[1]]).waiting).toHaveLength(1);
    expect(r.roster()).toEqual({});
    expect(r.receiveChanges([units[0]]).admitted).toHaveLength(2);
    expect(r.validate()).toEqual(normal.replica.validate());
    expect(r.receiveChanges(units).duplicates).toHaveLength(2);
  });

  it("identity_doc_second_initial_other_unit: before holding, both orders and KEY_BLOCKED release", () => {
    const real = initial();
    const second = A.encodeChange({ ...A.decodeChange(last(real)), message: "different initial" });
    const fakeDoc = A.applyChanges(A.init<Doc>(), [second])[0];
    const fill = edit(
      fakeDoc,
      (d) => {
        d.future = true;
      },
      rootWriter,
    );
    const badUnit = { ...rootWriter, actorSeq: 2, bytes: second };
    const fillUnit = unit(fill, { ...rootWriter, actorSeq: 3 });
    for (const units of [
      [unit(real), badUnit, fillUnit],
      [fillUnit, badUnit, unit(real)],
    ]) {
      const { replica, result } = IdentityReplica.fromChanges(units, options);
      expect(result.admitted).toEqual([checkChange(last(real)).hash]);
      expect(result.refused).toMatchObject([{ diagnostic: "INVALID_ROOT", held: false }]);
      expect(result.waiting).toEqual([checkChange(last(fill)).hash]);
      expect(replica.receiveChanges([badUnit]).refused[0]?.held).toBe(false);
    }
    // A blocked epoch yields no plaintext. The bad candidate never takes root's sequence slot.
    const r = IdentityReplica.empty(options);
    expect(r.receiveChanges([badUnit, fillUnit]).refused[0]?.diagnostic).toBe("INVALID_ROOT");
    expect(r.changes()).toEqual([]);
    expect(r.receiveChanges([unit(real)]).admitted).toHaveLength(1);
    expect(r.hasChange(checkChange(second).hash)).toBe(false);
    expect(IdentityReplica.fromSave(A.save(real), options, [unit(real)]).heads()).toEqual(
      r.heads(),
    );
    expect(() =>
      IdentityReplica.fromSave(A.save(fakeDoc), options, [unit(real), badUnit]),
    ).toThrow();
  });

  it("AI0 applies to duplicate bytes carried in unit 2 too", () => {
    const first = unit(initial());
    const r = IdentityReplica.fromChanges([first], options).replica;
    const out = r.receiveChanges([{ ...first, actorSeq: 2 }]);
    expect(out.duplicates).toEqual([]);
    expect(out.refused[0]).toMatchObject({ diagnostic: "INVALID_ROOT", held: false });
  });

  it("identity_doc_initial_without_unit_1", () => {
    const { doc, units } = filled();
    expect(() => IdentityReplica.fromSave(A.save(doc), options, [units[1]])).toThrow(/unit 1/);
    expect(() =>
      IdentityReplica.fromSave(A.save(doc), options, [{ ...units[0], actorSeq: 2 }, units[1]]),
    ).toThrow(/sequence 1/);
    expect(() => IdentityReplica.fromSave(A.save(doc), options, [units[0]])).toThrow(
      /verified carrying unit/,
    );
  });

  it("identity_snapshot_equivalence and codecs", () => {
    const { units } = filled();
    const r = IdentityReplica.fromChanges(units, options).replica;
    expect(identityCodec.dataProfile).toBe("org.openlfcp.identity.v1");
    expect(identitySnapshotCodec.dataProfile).toBe(identityCodec.dataProfile);
    expect(identityCodec.decode(identityCodec.encode(checkChange(units[0].bytes))).bytes).toEqual(
      units[0].bytes,
    );
    const restored = IdentityReplica.fromSnapshot(r.snapshot(), options, units);
    expect(restored.heads()).toEqual(r.heads());
    expect(restored.validate()).toEqual(r.validate());
    expect(identitySnapshotCodec.decode(identitySnapshotCodec.encode(r.save()))).toEqual(r.save());
    const receiver = IdentityReplica.empty(options);
    expect(receiver.receive(frameChange(units[0].bytes), rootWriter).admitted).toHaveLength(1);
    expect(() => receiver.receive(new Uint8Array([1]), rootWriter)).toThrow();
    expect(() => IdentityReplica.fromSave(new Uint8Array([1]), options, units)).toThrow();
  });

  it("snapshot replay refuses a malicious pairing write despite a valid initial proof", () => {
    const first = initial();
    const bad = edit(
      first,
      (d) => {
        d.roster[resourceRef] = {};
      },
      pairingWriter,
    );
    expect(() =>
      IdentityReplica.fromSave(A.save(bad), options, [unit(first), unit(bad, pairingWriter)]),
    ).toThrow(/UNAUTHORIZED_WRITER/);
  });

  it("rebuild excludes dependants and releases a held competing sequence", () => {
    const first = initial();
    const a = edit(first, (d) => {
      d.roster[resourceRef] = { profile: S("a"), endpoints: [], coordinator: S("") };
    });
    const b = edit(first, (d) => {
      d.roster[resourceRef] = { profile: S("b"), endpoints: [], coordinator: S("") };
    });
    const child = edit(
      a,
      (d) => {
        d.roster[resourceRef].name = S("child");
      },
      rootWriter,
    );
    const { replica, result } = IdentityReplica.fromChanges(
      [
        unit(first),
        unit(a, personalWriter),
        unit(b, { ...personalWriter, actorSeq: 2 }),
        unit(child, { ...rootWriter, actorSeq: 2 }),
      ],
      options,
    );
    expect(result.refused[0]).toMatchObject({ held: true, diagnostic: "ACTOR_EQUIVOCATION" });
    const rebuilt = replica.rebuildWithout([checkChange(last(a)).hash]);
    expect(rebuilt.result.waiting).toContain(checkChange(last(child)).hash);
    expect(rebuilt.replica.roster()[resourceRef]?.profile).toBe("b");
    expect(rebuilt.replica.roster()[resourceRef]?.name).toBeUndefined();
    expect(replica.roster()[resourceRef]?.name).toBe("child");
  });

  it("inherited depth and causal reference rules precede profile diagnostics", () => {
    const first = initial();
    const deep = edit(first, (d) => {
      let node = d.extensions;
      for (let i = 0; i < MAX_DOCUMENT_DEPTH + 1; i++) {
        node.x = {};
        node = node.x;
      }
    });
    const r = IdentityReplica.fromChanges([unit(first)], options).replica;
    expect(r.receiveChanges([unit(deep, personalWriter)]).refused[0]?.diagnostic).toBe(
      "INVALID_AUTOMERGE_BYTES",
    );
    const good = edit(first, (d) => {
      d.future = { value: S("ok") };
    });
    const malicious = A.decodeChange(
      last(
        edit(
          good,
          (d) => {
            d.future.value = S("outside history");
          },
          pairingWriter,
        ),
      ),
    );
    const bytes = A.encodeChange({ ...malicious, deps: [checkChange(last(first)).hash] });
    expect(
      r.receiveChanges([unit(good, personalWriter), { ...pairingWriter, bytes }]).refused[0]
        ?.diagnostic,
    ).toBe("INVALID_AUTOMERGE_BYTES");
  });

  it("typed writer creates scalar strings and uints, and preserves unknown fields", () => {
    expect(actor(rootWriter)).toBe(
      Array.from(deriveActorId(resource, root), (b) => b.toString(16).padStart(2, "0")).join(""),
    );
    const r = IdentityReplica.empty(options);
    const first = r.write({ ...rootWriter, actorSeq: 1n }, { intent: "identity.initialize" });
    expect(first.seq).toBe(1);
    r.write(
      { ...rootWriter, actorSeq: 2n },
      {
        intent: "roster.put",
        key: resourceRef,
        entry: {
          profile: "example.profile",
          endpoints: ["https://example.test"],
          coordinator: "https://example.test",
          name: "notes",
        },
      },
    );
    r.write(
      { ...personalWriter, signer: parsePrincipalRef(device.key) },
      {
        intent: "device.put",
        key: device.key,
        entry: { label: "phone", kind: 0, missing_keys: { [resourceRef]: [1, 4] } },
      },
    );
    r.write(pairingWriter, {
      intent: "request.put",
      key: device.key,
      entry: {
        descriptor: device.text,
        pairing: principalRef(pairingWriter.signer),
        label: "phone",
        kind: 0,
      },
    });
    expect(r.validate().problems).toEqual([]);
    expect(r.devices()[device.key]?.missing_keys).toEqual({ [resourceRef]: [1, 4] });
    const future = edit(
      A.load<Doc>(r.save()),
      (d) => {
        d.devices[device.key].future = { keep: true };
      },
      rootWriter,
    );
    expect(r.receiveChanges([unit(future, { ...rootWriter, actorSeq: 3 })]).refused).toEqual([]);
    r.write(
      { ...personalWriter, actorSeq: 2 },
      { intent: "device.put", key: device.key, entry: { label: "renamed", kind: 0 } },
    );
    const doc = A.load<Doc>(r.save());
    expect(doc.devices[device.key].future.keep).toBe(true);
    r.write({ ...rootWriter, actorSeq: 4 }, { intent: "roster.delete", key: resourceRef });
    expect(r.roster()).toEqual({});
  });

  it("uint64 unit sequences and missing_keys retain all bits", () => {
    const r = IdentityReplica.empty(options);
    r.write(rootWriter, { intent: "identity.initialize" });
    r.write(
      { ...personalWriter, signer: parsePrincipalRef(device.key), actorSeq: UINT64_MAX },
      {
        intent: "device.put",
        key: device.key,
        entry: {
          label: "phone",
          kind: 0,
          missing_keys: { [resourceRef]: [0, 2n ** 53n + 1n, UINT64_MAX] },
        },
      },
    );
    expect(r.devices()[device.key]?.missing_keys).toEqual({
      [resourceRef]: [0, 2n ** 53n + 1n, UINT64_MAX],
    });
    expect(r.validate().problems).toEqual([]);
  });

  it("local failed writes leave state and pending queues unchanged", () => {
    const { replica } = IdentityReplica.fromChanges(filled().units, options);
    const before = replica.heads();
    expect(() =>
      replica.write(rootWriter, {
        intent: "device.put",
        key: device.key,
        entry: { label: "phone", kind: 0, missing_keys: { [resourceRef]: [] } },
      }),
    ).toThrow(/own missing_keys/);
    expect(() =>
      replica.write(pairingWriter, { intent: "roster.delete", key: resourceRef }),
    ).toThrow(/UNAUTHORIZED_WRITER/);
    expect(() =>
      replica.write(personalWriter, {
        intent: "request.put",
        key: device.key,
        entry: {
          descriptor: "bad",
          pairing: principalRef(pairingWriter.signer),
          label: "bad",
          kind: 0,
        },
      }),
    ).toThrow();
    expect(replica.heads()).toEqual(before);
    expect(replica.receiveChanges([]).waiting).toEqual([]);
  });
});

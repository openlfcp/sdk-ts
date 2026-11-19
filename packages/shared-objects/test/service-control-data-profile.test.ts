import { type DataUnitId, dataUnitId, type PrincipalId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { checkChange } from "../src/admission/framing.js";
import {
  type ServiceControlChanged,
  ServiceControlDataProfile,
  type ServiceControlIntent,
  ServiceControlReplica,
  type ServiceControlSignerClass,
} from "../src/service-control/index.js";
import {
  approval,
  B,
  personal,
  principalRef,
  request,
  resource,
  root,
  SERVICE,
  STATUS,
  T0,
  uid,
} from "./support/service-control.js";

const options = { resource, root, genesisSigner: root };
const classes = new Map<string, ServiceControlSignerClass>([
  [toHex(root), "root"],
  [toHex(personal), "personal"],
  [toHex(B), "service-device"],
]);
/** The class the applier's Control state would give (here: a fixed table by signer). */
const signerClassOf = (u: { actor: PrincipalId; control?: unknown }) =>
  u.control === "at-control-ref" ? (classes.get(toHex(u.actor)) ?? "other") : "other";

let n = 0;
const unitId = (): DataUnitId => dataUnitId(new Uint8Array(32).fill(++n));

/** A writer's units: its own replica writes the changes another client receives. */
function history() {
  const source = ServiceControlReplica.empty(options);
  const units: {
    unit: { unitId: DataUnitId; actor: PrincipalId; seq: number; control: string };
    value: ReturnType<typeof checkChange>;
  }[] = [];
  const write = (signer: PrincipalId, intents: ServiceControlIntent[], seq = 2) => {
    const cls = classes.get(toHex(signer)) as ServiceControlSignerClass;
    const change = source.write({ signer, signerClass: cls, actorSeq: seq }, intents);
    if (change === null) throw new Error("no change");
    units.push({
      unit: { unitId: unitId(), actor: signer, seq, control: "at-control-ref" },
      value: checkChange(change.bytes),
    });
  };
  write(root, [{ intent: "initialize", attemptId: "attempt-1", createdAt: T0 }], 1);
  write(root, [{ intent: "approval.create", approval: approval(B) as never }]);
  write(B, [
    { intent: "service.put", fields: SERVICE },
    { intent: "status.put", fields: STATUS },
  ]);
  write(personal, [{ intent: "request.create", rid: uid(1), request: request("check") as never }]);
  return units;
}

describe("ServiceControlDataProfile: C through the client's Data Unit applier", () => {
  it("merges units in any order, by the signer's class at control_ref, and notifies", () => {
    const units = history();
    const profile = new ServiceControlDataProfile({ ...options, signerClassOf });
    const seen: ServiceControlChanged[] = [];
    profile.onChanged((e) => seen.push(e));
    // The request first: it waits for the changes it depends on.
    const last = units[3] as (typeof units)[number];
    const early = profile.apply(last.unit, last.value);
    expect("pending" in early).toBe(true);
    expect(profile.has(last.unit.unitId)).toBe(true);
    const r = profile.applyBatch(units.slice(0, 3));
    expect(r.rejected).toEqual([]);
    expect(r.pending).toEqual([]);
    expect(r.merged.map(toHex).sort()).toEqual(units.map((u) => toHex(u.unit.unitId)).sort());
    const s = profile.state();
    expect(s.status?.state).toBe("running");
    expect(s.requests[uid(1)]?.op).toBe("check");
    expect(seen).toHaveLength(1);
    expect(seen[0]?.origin).toBe("remote");
    expect(seen[0]?.keys).toEqual(
      expect.arrayContaining([
        "service",
        "status",
        `requests/${uid(1)}`,
        `approvals/${principalRef(B)}`,
      ]),
    );
  });

  it("refuses a service write without its class at control_ref, and its dependants wait", () => {
    const units = history();
    const profile = new ServiceControlDataProfile({ ...options, signerClassOf });
    profile.applyBatch(units.slice(0, 2));
    const service = units[2] as (typeof units)[number];
    const r = profile.applyBatch([
      { unit: { ...service.unit, control: "elsewhere" }, value: service.value },
    ]);
    expect(r.rejected.map((x) => x.diagnostic)).toEqual(["UNAUTHORIZED_WRITER"]);
    expect(profile.state().status).toBeUndefined();
  });

  it("commits local writes: a refused one throws before any unit, an unchanged one writes nothing", () => {
    const units = history();
    const plugin = new ServiceControlDataProfile({ ...options, signerClassOf });
    plugin.applyBatch(units);
    const seen: ServiceControlChanged[] = [];
    plugin.onChanged((e) => seen.push(e));
    const binding = plugin.commitBinding(personal, "personal");
    const staged = binding.stage([
      { intent: "cancel.create", rid: uid(1), cancel: { reason: "user", at: T0 } },
    ]);
    expect(staged?.values).toHaveLength(1);
    expect(staged?.affectedNodeIds).toEqual([`cancels/${uid(1)}`]);
    staged?.apply();
    const hash = String(staged?.values[0]?.hash);
    // Staged: no unit carries the change yet; committed: its unit does.
    expect(plugin.unitsOf(hash)).toEqual([]);
    const own = unitId();
    staged?.committed([own]);
    expect(plugin.unitsOf(hash).map(toHex)).toEqual([toHex(own)]);
    expect(seen.map((e) => [e.origin, e.keys])).toEqual([["local", [`cancels/${uid(1)}`]]]);
    expect(() =>
      binding.stage([{ intent: "status.put", fields: { state: "paused" } }]),
    ).toThrowError(expect.objectContaining({ diagnostic: "UNAUTHORIZED_WRITER" }));
    const service = new ServiceControlDataProfile({ ...options, signerClassOf });
    service.applyBatch(units);
    expect(
      service.commitBinding(B, "service-device").stage([{ intent: "status.put", fields: STATUS }]),
    ).toBeNull();
    // A staged write that is not committed is taken back.
    const again = binding.stage([
      { intent: "request.create", rid: uid(2), request: request("check") as never },
    ]);
    again?.revert();
    expect(plugin.state().requests[uid(2)]).toBeUndefined();
    expect(plugin.replica.validate().requests[uid(2)]).toBeUndefined();
  });

  it("excludes a merged unit and rebuilds; its dependants wait again", () => {
    const units = history();
    const profile = new ServiceControlDataProfile({ ...options, signerClassOf });
    profile.applyBatch(units);
    const approvalUnit = (units[1] as (typeof units)[number]).unit.unitId;
    const r = profile.exclude([approvalUnit]);
    // B's service write depended on the approval (its class came from it).
    expect(r.pending.map(toHex)).toContain(toHex((units[2] as (typeof units)[number]).unit.unitId));
    expect(profile.state().approvals).toEqual({});
    expect(profile.has(approvalUnit)).toBe(false);
  });

  it("publishes Snapshots and loads none (§2.2)", () => {
    const profile = new ServiceControlDataProfile({ ...options, signerClassOf });
    profile.applyBatch(history());
    const binding = profile.snapshotBinding();
    expect("load" in binding).toBe(false);
    const save = binding.current();
    expect(binding.codec.decode(binding.codec.encode(save))).toEqual(save);
  });
});

/** personal's alternative to the request of history(): the same Automerge sequence, another change. */
function alternative(units: ReturnType<typeof history>) {
  const { replica } = ServiceControlReplica.fromChanges(
    units.slice(0, 3).map(({ unit, value }) => ({
      signer: unit.actor,
      actorSeq: unit.seq,
      signerClass: classes.get(toHex(unit.actor)) as ServiceControlSignerClass,
      bytes: value.bytes,
    })),
    options,
  );
  const change = replica.write({ signer: personal, signerClass: "personal", actorSeq: 2 }, [
    { intent: "request.create", rid: uid(9), request: request("check") as never },
  ]);
  if (change === null) throw new Error("no change");
  return {
    unit: { unitId: unitId(), actor: personal, seq: 2, control: "at-control-ref" },
    value: checkChange(change.bytes),
  };
}

describe("ServiceControlDataProfile.exclude: an excluded unit is never applied (W §19.1)", () => {
  it("a waiting unit excluded before its dependencies arrive", () => {
    const units = history();
    const profile = new ServiceControlDataProfile({ ...options, signerClassOf });
    const request = units[3] as (typeof units)[number];
    expect("pending" in profile.apply(request.unit, request.value)).toBe(true);
    profile.exclude([request.unit.unitId]);
    expect(profile.has(request.unit.unitId)).toBe(false);
    profile.applyBatch(units.slice(0, 3));
    expect(profile.state().status?.state).toBe("running");
    expect(profile.state().requests).toEqual({});
    expect(profile.replica.hasChange(request.value.hash)).toBe(false);
  });

  it("a merged unit excluded after its dependencies arrived", () => {
    const units = history();
    const profile = new ServiceControlDataProfile({ ...options, signerClassOf });
    profile.applyBatch(units);
    const request = units[3] as (typeof units)[number];
    expect(profile.state().requests[uid(1)]).toBeDefined();
    profile.exclude([request.unit.unitId]);
    expect(profile.state().requests).toEqual({});
    // Later deliveries (another catch-up) do not bring it back.
    profile.applyBatch(units.slice(0, 3));
    expect(profile.state().requests).toEqual({});
  });

  it("a held unit excluded, then the change that held it excluded too", () => {
    const units = history();
    const alt = alternative(units);
    const profile = new ServiceControlDataProfile({ ...options, signerClassOf });
    const r = profile.applyBatch([...units, alt]);
    expect(r.held.map(toHex)).toEqual([toHex(alt.unit.unitId)]);
    profile.exclude([alt.unit.unitId]);
    // Excluding the request frees the actor sequence: the held alternative must not take it.
    const freed = profile.exclude([(units[3] as (typeof units)[number]).unit.unitId]);
    expect(freed.released).toEqual([]);
    expect(profile.state().requests).toEqual({});
    expect(profile.replica.hasChange(alt.value.hash)).toBe(false);
  });

  it("a mixed exclusion of merged, waiting and held units", () => {
    const units = history();
    const alt = alternative(units);
    const profile = new ServiceControlDataProfile({ ...options, signerClassOf });
    profile.applyBatch([units[0], units[1], units[3], alt] as typeof units);
    // B's service write is still to come; the request merged, the alternative held.
    profile.exclude([
      (units[1] as (typeof units)[number]).unit.unitId,
      (units[3] as (typeof units)[number]).unit.unitId,
      alt.unit.unitId,
    ]);
    profile.applyBatch([units[2]] as typeof units);
    const s = profile.state();
    expect(s.approvals).toEqual({});
    expect(s.requests).toEqual({});
    // B's write needed the approval for its class: it waits, it is not admitted.
    expect(s.status).toBeUndefined();
  });
});

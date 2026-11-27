import { describe, it, expect } from "vitest";
import { dataUnitId } from "@openlfcp/core";
import { checkChange } from "../src/admission/framing.js";
import { ServiceControlDataProfile, ServiceControlReplica } from "../src/service-control/index.js";
import { resource, root, T0, uid, request } from "./support/service-control.js";

describe("ServiceControlDataProfile snapshot load", () => {
  it("keeps a merged unit the Snapshot does not carry", () => {
    const options = { resource, root, genesisSigner: root };
    const source = ServiceControlReplica.empty(options);
    const writer = { signer: root, signerClass: "root" as const, actorSeq: 1 };
    const initial = source.write(writer, [{ intent: "initialize", attemptId: "a", createdAt: T0 }])!;
    const initialUnit = { unitId: dataUnitId(new Uint8Array(32).fill(1)), actor: root, seq: 1, bytes: initial.bytes };
    const save = source.save();
    const tail = source.write({ ...writer, actorSeq: 2 }, [{ intent: "request.create", rid: uid(1), request: request("check") as never }])!;
    const tailUnit = { unitId: dataUnitId(new Uint8Array(32).fill(2)), actor: root, seq: 2, bytes: tail.bytes };
    const profile = new ServiceControlDataProfile({ ...options, signerClassOf: () => "root", coveredUnits: () => [initialUnit, tailUnit] });
    profile.applyBatch([{ unit: initialUnit, value: checkChange(initial.bytes) }, { unit: tailUnit, value: checkChange(tail.bytes) }]);
    expect(profile.state().requests[uid(1)]?.op).toBe("check");
    profile.snapshotBinding().load?.(save);
    expect(profile.state().requests[uid(1)]?.op).toBe("check");
    expect(profile.has(tailUnit.unitId)).toBe(true);
  });
});

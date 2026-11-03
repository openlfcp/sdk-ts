import { UINT64_MAX } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { IdentityReplica } from "../src/identity/index.js";
import { parsePrincipalRef } from "../src/values.js";
import { device, options, personalWriter, resourceRef, rootWriter } from "./support/identity.js";

describe("identity uint64 epochs", () => {
  it("large values replay through snapshots, continuations and exclusion", () => {
    const r = IdentityReplica.empty(options);
    const first = r.write(rootWriter, { intent: "identity.initialize" });
    const writer = {
      ...personalWriter,
      signer: parsePrincipalRef(device.key),
      actorSeq: UINT64_MAX,
    };
    const big = r.write(writer, {
      intent: "device.put",
      key: device.key,
      entry: { label: "phone", kind: 0, missing_keys: { [resourceRef]: [UINT64_MAX] } },
    });
    const units = [
      { ...rootWriter, bytes: first.bytes },
      { ...writer, bytes: big.bytes },
    ];
    const restored = IdentityReplica.fromSave(r.save(), options, units);
    expect(restored.validate()).toEqual(r.validate());
    const next = restored.write(
      { ...rootWriter, actorSeq: 2 },
      { intent: "device.put", key: device.key, entry: { label: "updated", kind: 0 } },
    );
    expect(next.deps).toContain(big.hash);
    expect(restored.devices()[device.key]?.missing_keys).toEqual({ [resourceRef]: [UINT64_MAX] });
    const rebuilt = restored.rebuildWithout([big.hash]);
    expect(rebuilt.result.waiting).toContain(next.hash);
    expect(rebuilt.replica.devices()).toEqual({});
  });
});

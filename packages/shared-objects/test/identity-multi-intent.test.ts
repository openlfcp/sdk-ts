import { describe, expect, it } from "vitest";
import { IdentityReplica } from "../src/identity/index.js";
import { device, options, resourceRef, rootWriter } from "./support/identity.js";

describe("identity writes with several intents (IDENTITY-PROFILE-01 §5.1, §5.3 step 6)", () => {
  it("puts the roster and a device entry in one change that a second replica admits", () => {
    const r = IdentityReplica.empty(options);
    const first = r.write(rootWriter, { intent: "identity.initialize" });
    const writer = { ...rootWriter, actorSeq: 2 };
    const fill = r.write(writer, [
      {
        intent: "roster.put",
        key: resourceRef,
        entry: { profile: "org.example.v1", endpoints: [], coordinator: "wss://x.test/ws" },
      },
      { intent: "device.put", key: device.key, entry: { label: "laptop", kind: 0 } },
    ]);
    expect(fill.deps).toEqual([first.hash]);
    expect(Object.keys(r.roster())).toEqual([resourceRef]);
    expect(r.devices()[device.key]).toEqual({ label: "laptop", kind: 0 });
    const other = IdentityReplica.empty(options);
    const result = other.receiveChanges([
      { ...rootWriter, bytes: first.bytes },
      { ...writer, bytes: fill.bytes },
    ]);
    expect(result.admitted).toEqual([first.hash, fill.hash]);
    expect(other.validate()).toEqual(r.validate());
  });

  it("refuses the whole change when one intent is invalid", () => {
    const r = IdentityReplica.empty(options);
    r.write(rootWriter, { intent: "identity.initialize" });
    const heads = r.heads();
    expect(() =>
      r.write({ ...rootWriter, actorSeq: 2 }, [
        { intent: "device.put", key: device.key, entry: { label: "laptop", kind: 0 } },
        { intent: "device.put", key: "not-a-ref", entry: { label: "x", kind: 0 } },
      ]),
    ).toThrow();
    expect(r.heads()).toEqual(heads);
    expect(() => r.write({ ...rootWriter, actorSeq: 2 }, [])).toThrow(/no intent/);
  });
});

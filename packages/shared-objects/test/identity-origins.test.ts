import { describe, expect, it } from "vitest";
import { IdentityReplica } from "../src/identity/index.js";
import { principalRef } from "../src/values.js";
import {
  device,
  options,
  other,
  otherWriter,
  pairing,
  pairingWriter,
  rootWriter,
  secondDevice,
} from "./support/identity.js";

const entry = (d: { text: string }, label: string) => ({
  descriptor: d.text,
  pairing: principalRef(pairing),
  label,
  kind: 0 as const,
});

describe("identity entry origins (IDENTITY-PROFILE-01 §5.3 step 4)", () => {
  it("names every admitted change that wrote a request, whatever the delivery order", () => {
    const r = IdentityReplica.empty(options);
    const first = r.write(rootWriter, { intent: "identity.initialize" });
    const a = r.write(pairingWriter, {
      intent: "request.put",
      key: device.key,
      entry: entry(device, "one"),
    });
    const b = r.write(
      { ...pairingWriter, actorSeq: 2 },
      { intent: "request.put", key: secondDevice.key, entry: entry(secondDevice, "two") },
    );
    expect(r.origins("requests", device.key).map((o) => o.hash)).toEqual([a.hash]);
    expect(r.origins("requests", secondDevice.key).map((o) => o.hash)).toEqual([b.hash]);
    // A replica that receives the dependent change first holds it; origins stay exact.
    const other = IdentityReplica.empty(options);
    other.receiveChanges([{ ...pairingWriter, actorSeq: 2, bytes: b.bytes }]);
    other.receiveChanges([
      { ...rootWriter, bytes: first.bytes },
      { ...pairingWriter, bytes: a.bytes },
    ]);
    expect(other.origins("requests", device.key).map((o) => o.hash)).toEqual([a.hash]);
    expect(other.origins("requests", secondDevice.key).map((o) => o.hash)).toEqual([b.hash]);
    expect(other.origins("requests", device.key)[0]?.signer).toEqual(pairing);
    // A later change to the entry is named too; another table's entry is not.
    const c = other.write(
      { ...pairingWriter, actorSeq: 3 },
      {
        intent: "request.put",
        key: device.key,
        entry: { ...entry(device, "one"), requested_at: "2026-11-04T00:00:00Z" },
      },
    );
    expect(other.origins("requests", device.key).map((o) => o.hash)).toEqual([a.hash, c.hash]);
    expect(other.origins("roster", device.key)).toEqual([]);
  });

  it("names only the current entry's changes, not those of a deleted predecessor", () => {
    const r = IdentityReplica.empty(options);
    r.write(rootWriter, { intent: "identity.initialize" });
    r.write(pairingWriter, { intent: "request.put", key: device.key, entry: entry(device, "one") });
    // The managing device rejects it: the root deletes the request (§5.3 step 4).
    r.write({ ...rootWriter, actorSeq: 2 }, { intent: "request.delete", key: device.key });
    // A new session's pairing device writes a new request under the same key.
    const again = r.write(otherWriter, {
      intent: "request.put",
      key: device.key,
      entry: { ...entry(device, "again"), pairing: principalRef(other) },
    });
    expect(r.origins("requests", device.key)).toEqual([{ hash: again.hash, signer: other }]);
    r.write({ ...rootWriter, actorSeq: 3 }, { intent: "request.delete", key: device.key });
    expect(r.origins("requests", device.key)).toEqual([]);
  });
});

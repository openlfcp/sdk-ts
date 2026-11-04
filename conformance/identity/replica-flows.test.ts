// The identity flows with the real Identity Resource document
// (IdentityReplica): the pairing request is admitted for the pairing
// device's class (AI4), the device entry and the request deletion of
// §5.3 step 6 and the roster entry of §7.3 are admitted for the managing
// devices, and the merged document stays valid.
import {
  createIdentityResource,
  createResourceAsDevice,
  fetchDeks,
  loadIdentityDocument,
  principalRefOf,
  resourceRef,
  revokeDevice,
  sealIdentityUnit,
  syncChain,
} from "@openlfcp/client";
import type { ResourceId } from "@openlfcp/core";
import { describe, expect, test } from "vitest";
import { MemoryCoordinator } from "../../packages/client/test/identity/memory-coordinator.js";
import { party, URL } from "../../packages/client/test/identity/support.js";
import { hostResource, type Node, node, pair } from "../../packages/client/test/identity/world.js";
import { replicaPort } from "./replica-port.js";

describe("identity flows with IdentityReplica", { timeout: 120_000 }, () => {
  test("pairing, a Resource from a device, and the document every device reads", async () => {
    const server = new MemoryCoordinator();
    const real = (n: number) => ({ ...node(server, party(n)), document: replicaPort });
    const P = real(1);
    const X = await hostResource(server, P as never);
    const created = await createIdentityResource({ ...P, url: URL, label: "laptop", roster: [X] });
    if (created.kind !== "created") throw new Error(created.kind);
    const w = { server };
    const A = await pair(w, P as never, 2, "full", { document: replicaPort as never });
    const B = await pair(w, A, 3, "edit", { document: replicaPort as never });
    const made = await createResourceAsDevice({
      ...A,
      dataProfile: "org.example.v1",
      url: URL,
      name: "From A",
    });
    if (made.kind !== "created") throw new Error(made.kind);

    for (const who of [P, A, B]) {
      const channel = await server.network().connect(who.installation.signer, URL);
      const chain = await syncChain(who.storage, channel, created.identity);
      const doc = replicaPort(created.identity, party(1).signer.descriptor.principalId);
      await loadIdentityDocument({
        channel,
        chain,
        deks: await fetchDeks(who.storage, who.secrets, channel, chain, who.installation),
        doc,
      });
      const v = doc.replica().validate();
      expect(v.usable).toBe(true);
      expect(v.problems).toEqual([]);
      expect(Object.keys(v.requests)).toEqual([]);
      expect(Object.keys(v.devices).sort()).toEqual(
        [1, 2, 3].map((n) => principalRefOf(party(n).signer.descriptor.principalId)).sort(),
      );
      expect(Object.keys(v.roster).sort()).toEqual(
        [resourceRef(X.resource), resourceRef(made.resource)].sort(),
      );
    }
  });

  test("revoking a device with its own missing_keys hint: the flag is set, the hint stays the device's (AI5)", async () => {
    const server = new MemoryCoordinator();
    const P = { ...node(server, party(1)), document: replicaPort };
    const X = await hostResource(server, P as never);
    const created = await createIdentityResource({ ...P, url: URL, label: "laptop", roster: [X] });
    if (created.kind !== "created") throw new Error(created.kind);
    const I = created.identity;
    const A = await pair({ server }, P as never, 2, "full", { document: replicaPort as never });
    const key = principalRefOf(party(2).signer.descriptor.principalId);
    const open = async (who: Node) => {
      const channel = await server.network().connect(who.installation.signer, URL);
      const chain = await syncChain(who.storage, channel, I as ResourceId);
      const doc = replicaPort(I, party(1).signer.descriptor.principalId);
      const deks = await fetchDeks(who.storage, who.secrets, channel, chain, who.installation);
      const load = await loadIdentityDocument({ channel, chain, deks, doc });
      return { channel, chain, deks, doc, load };
    };
    // The device writes its own hint (AI5 admits it from the device only).
    const a = await open(A);
    const own = a.doc.devices().get(key);
    if (own === undefined) throw new Error("no device entry");
    const hint = { [resourceRef(X.resource)]: [0] };
    const bytes = await sealIdentityUnit({
      storage: A.storage,
      chain: a.chain,
      deks: a.deks,
      signer: A.installation.signer,
      doc: a.doc,
      latest: a.load.latest,
      intents: [{ intent: "device.put", key, entry: { ...own, missing_keys: hint } }],
    });
    expect((await a.channel.putDataUnit(I, bytes)).kind).toBe("ack");
    const r = await revokeDevice({
      ...P,
      device: party(2).signer.descriptor.principalId,
      reason: 0n,
    } as never);
    if (r.kind !== "revoked") throw new Error(r.kind);
    // Read back from the coordinator with a fresh replica: the root's flag and the device's hint.
    const p = await open(P as never);
    expect(p.doc.replica().validate().problems).toEqual([]);
    expect(p.doc.devices().get(key)).toMatchObject({ revoked: true, missing_keys: hint });
  });
});
